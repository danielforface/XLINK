use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::Parser;
use nexus_core::{
    ControlMessage, FramePacket, SecurityError, SessionCredentials, SessionState,
    SessionStateMachine,
};
use nexus_display::{spawn_remote_viewer, ScreenCapturer, ViewerFrame, ViewerInputEvent};
use nexus_input::{
    show_host_consent_dialog, InputController, KeyboardPreview, MousePreview,
    SessionState as InputSessionState,
};
use nexus_network::{bind_client, bind_server, normalize_fingerprint_hex};
use quinn::{RecvStream, SendStream, VarInt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{error, info, warn};

const PROTOCOL_VERSION: u16 = 1;
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_FPS: u16 = 30;
const MIN_FPS: u16 = 1;
const MAX_FPS: u16 = 60;
const ACCESS_ID_VERSION: u8 = 1;

#[derive(Debug)]
enum LaunchMode {
    Server {
        port: u16,
        fps: u16,
        inject_input: bool,
        advertise_addr: Option<SocketAddr>,
    },
    Client {
        server_addr: SocketAddr,
        fingerprint: String,
        target_id: String,
        access_password: String,
        display_name: Option<String>,
    },
}

#[derive(Debug)]
struct IncomingAuth {
    requester_id: String,
    target_id: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessIdPayload {
    version: u8,
    server_addr: String,
    fingerprint: String,
    target_id: String,
}

#[derive(Debug)]
struct ParsedAccessId {
    server_addr: SocketAddr,
    fingerprint: String,
    target_id: String,
}

#[derive(Debug, Parser)]
#[command(author, version, about = "NexusP2P remote support engine for Windows")]
struct Cli {
    #[arg(long, conflicts_with_all = ["client", "access_id"])]
    server: bool,
    #[arg(long, value_name = "HOST:PORT", conflicts_with_all = ["server", "access_id"])]
    client: Option<SocketAddr>,
    #[arg(long, value_name = "SHA256_HEX", requires = "client")]
    fingerprint: Option<String>,
    #[arg(long, value_name = "TARGET_ID", requires = "client")]
    target_id: Option<String>,
    #[arg(
        long,
        value_name = "ACCESS_ID",
        conflicts_with_all = ["server", "client", "fingerprint", "target_id"]
    )]
    access_id: Option<String>,
    #[arg(long, value_name = "ACCESS_PASSWORD", conflicts_with = "server")]
    access_password: Option<String>,
    #[arg(long, default_value_t = 5000)]
    port: u16,
    #[arg(long, default_value_t = DEFAULT_FPS, requires = "server")]
    fps: u16,
    #[arg(long, requires = "server")]
    inject_input: bool,
    #[arg(long, value_name = "NAME", conflicts_with = "server")]
    display_name: Option<String>,
    #[arg(long, value_name = "HOST:PORT", requires = "server")]
    advertise: Option<SocketAddr>,
    #[arg(long, conflicts_with_all = ["server", "client", "access_id"])]
    interactive: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let launch_mode = resolve_launch_mode(cli).await?;

    match launch_mode {
        LaunchMode::Server {
            port,
            fps,
            inject_input,
            advertise_addr,
        } => run_server(port, fps, inject_input, advertise_addr).await,
        LaunchMode::Client {
            server_addr,
            fingerprint,
            target_id,
            access_password,
            display_name,
        } => {
            run_client(
                server_addr,
                fingerprint,
                target_id,
                access_password,
                display_name,
            )
            .await
        }
    }
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,quinn=warn".to_string());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

async fn resolve_launch_mode(cli: Cli) -> Result<LaunchMode> {
    if cli.server {
        return Ok(LaunchMode::Server {
            port: cli.port,
            fps: cli.fps,
            inject_input: cli.inject_input,
            advertise_addr: cli.advertise,
        });
    }

    if let Some(access_id) = cli.access_id {
        let parsed = parse_access_id(&access_id).context("invalid --access-id value")?;
        let access_password = cli
            .access_password
            .context("--access-password is required with --access-id")?;

        return Ok(LaunchMode::Client {
            server_addr: parsed.server_addr,
            fingerprint: parsed.fingerprint,
            target_id: parsed.target_id,
            access_password,
            display_name: cli.display_name,
        });
    }

    if let Some(server_addr) = cli.client {
        let fingerprint = cli
            .fingerprint
            .context("--fingerprint is required with --client")?;
        let fingerprint = normalize_fingerprint_hex(&fingerprint)
            .context("invalid --fingerprint value")?;
        let target_id = cli
            .target_id
            .context("--target-id is required with --client")?;
        let access_password = cli
            .access_password
            .context("--access-password is required with --client")?;

        return Ok(LaunchMode::Client {
            server_addr,
            fingerprint,
            target_id,
            access_password,
            display_name: cli.display_name,
        });
    }

    if cli.interactive || (!cli.server && cli.client.is_none() && cli.access_id.is_none()) {
        return prompt_launch_mode_interactive().await;
    }

    bail!("choose host mode or provide --client/--access-id")
}

async fn run_server(
    port: u16,
    requested_fps: u16,
    inject_input: bool,
    advertise_addr: Option<SocketAddr>,
) -> Result<()> {
    let fps = requested_fps.clamp(MIN_FPS, MAX_FPS);
    if fps != requested_fps {
        warn!(requested_fps, fps, "fps value clamped to supported range");
    }
    let frame_interval_ms = (1000_u64 / fps as u64).max(1);

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
    let server = bind_server(bind_addr).await?;
    let advertised_addr = advertised_server_addr(bind_addr, advertise_addr);
    let credentials = SessionCredentials::generate();
    let access_id = build_access_id(
        advertised_addr,
        &server.certificate_fingerprint,
        &credentials.session_id,
    )?;

    info!(
        %bind_addr,
        %advertised_addr,
        fps,
        inject_input,
        cert_bytes = server.certificate_der.len(),
        fingerprint = %server.certificate_fingerprint,
        "server endpoint ready"
    );
    println!(
        "Server certificate SHA-256 fingerprint: {}",
        server.certificate_fingerprint
    );
    println!("Session ID: {}", credentials.session_id);
    println!("Access Password: {}", credentials.access_password);
    println!("Access ID: {access_id}");

    let session_state = Arc::new(SessionStateMachine::new());
    session_state.transition(SessionState::Authenticating)?;

    let connection = server.accept().await?;
    let remote_addr = connection.remote_address();
    let (mut control_send, mut control_recv) = connection
        .accept_bi()
        .await
        .context("client did not open a control stream")?;

    let incoming_auth = wait_for_auth_request(&mut control_recv).await?;

    if let Err(auth_error) = credentials.verify(&incoming_auth.target_id, &incoming_auth.password) {
        let _ = session_state.transition(SessionState::Rejected);
        error!(
            ?auth_error,
            remote = %remote_addr,
            requester_id = %incoming_auth.requester_id,
            "SECURITY: authentication failed"
        );

        let _ = send_message(
            &mut control_send,
            &ControlMessage::AuthResult {
                success: false,
                message: "AuthenticationFailed".to_string(),
            },
        )
        .await;

        connection.close(VarInt::from_u32(1), b"authentication failed");
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

    send_message(
        &mut control_send,
        &ControlMessage::AuthResult {
            success: true,
            message: "AuthenticationSucceeded".to_string(),
        },
    )
    .await
    .context("failed to send authentication result")?;

    session_state.transition(SessionState::PendingConsent)?;

    let approved = prompt_for_host_consent(&incoming_auth.requester_id).await?;
    send_message(&mut control_send, &ControlMessage::SessionConsent { approved })
        .await
        .context("failed to send session consent result")?;

    if !approved {
        let _ = session_state.transition(SessionState::Rejected);
        error!(
            requester_id = %incoming_auth.requester_id,
            remote = %remote_addr,
            error = %SecurityError::UserConsentDenied,
            "SECURITY: local user denied consent"
        );
        connection.close(VarInt::from_u32(2), b"user denied consent");
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

    session_state.transition(SessionState::Active)?;

    let input = Arc::new(InputController::new()?);
    input.set_state(InputSessionState::Active);

    send_message(
        &mut control_send,
        &ControlMessage::Ack(format!(
            "session-approved mode={}",
            if inject_input { "inject" } else { "preview" }
        )),
    )
    .await
    .context("failed to send session approval acknowledgement")?;

    let session_state_for_control = Arc::clone(&session_state);
    let input_for_control = Arc::clone(&input);
    let control_task = tokio::spawn(async move {
        loop {
            match recv_message::<ControlMessage>(&mut control_recv).await {
                Ok(ControlMessage::SimulatedMouseMove { x_norm, y_norm }) => {
                    if !session_state_for_control.is_active() {
                        error!(
                            state = ?session_state_for_control.state(),
                            "SECURITY: blocked mouse event while session not active"
                        );
                        continue;
                    }

                    match apply_mouse_event(&input_for_control, x_norm, y_norm, inject_input) {
                        Ok(preview) => {
                            info!(
                                x_norm,
                                y_norm,
                                absolute_x = preview.absolute_x,
                                absolute_y = preview.absolute_y,
                                mode = if inject_input { "inject" } else { "preview" },
                                "processed mouse move"
                            );
                        }
                        Err(error) => {
                            warn!(
                                ?error,
                                mode = if inject_input { "inject" } else { "preview" },
                                "failed mouse processing"
                            );
                        }
                    }

                    if let Err(error) = send_message(
                        &mut control_send,
                        &ControlMessage::Ack(format!(
                            "{} move to ({x_norm:.3}, {y_norm:.3})",
                            if inject_input { "injected" } else { "previewed" }
                        )),
                    )
                    .await
                    {
                        error!(?error, "failed to send mouse acknowledgement");
                        break;
                    }
                }
                Ok(ControlMessage::SimulatedKeyEvent {
                    virtual_key,
                    pressed,
                }) => {
                    if !session_state_for_control.is_active() {
                        error!(
                            state = ?session_state_for_control.state(),
                            "SECURITY: blocked key event while session not active"
                        );
                        continue;
                    }

                    match apply_keyboard_event(&input_for_control, virtual_key, pressed, inject_input)
                    {
                        Ok(preview) => {
                            info!(
                                virtual_key,
                                pressed = preview.pressed,
                                flags = preview.flags,
                                mode = if inject_input { "inject" } else { "preview" },
                                "processed key event"
                            );
                        }
                        Err(error) => {
                            warn!(
                                ?error,
                                mode = if inject_input { "inject" } else { "preview" },
                                "failed key processing"
                            );
                        }
                    }

                    if let Err(error) = send_message(
                        &mut control_send,
                        &ControlMessage::Ack(format!(
                            "{} keyboard event vk={virtual_key} pressed={pressed}",
                            if inject_input { "injected" } else { "previewed" }
                        )),
                    )
                    .await
                    {
                        error!(?error, "failed to send keyboard acknowledgement");
                        break;
                    }
                }
                Ok(other) => {
                    warn!(?other, "ignoring unexpected control message");
                }
                Err(error) => {
                    info!(?error, "control stream closed");
                    break;
                }
            }
        }
    });

    let mut frame_stream = connection
        .open_uni()
        .await
        .context("failed to open frame stream")?;
    let mut capturer = ScreenCapturer::new()?;
    let mut ticker = time::interval(Duration::from_millis(frame_interval_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !session_state.is_active() {
                    error!(
                        state = ?session_state.state(),
                        "SECURITY: blocked frame transmission while session not active"
                    );
                    continue;
                }

                let frame = capturer.capture_frame()?;
                let packet = FramePacket {
                    sequence: frame.frame_index,
                    width: frame.width,
                    height: frame.height,
                    stride: frame.stride,
                    pixels: frame.pixels.to_vec(),
                };

                if let Err(error) = send_message(&mut frame_stream, &packet).await {
                    info!(?error, "frame stream ended");
                    break;
                }

                info!(sequence = packet.sequence, bytes = packet.pixels.len(), "sent frame");
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                info!("server shutdown requested");
                break;
            }
        }
    }

    input.set_state(InputSessionState::Inactive);
    let _ = session_state.transition(SessionState::Terminated);
    let _ = frame_stream.finish().await;
    connection.close(VarInt::from_u32(0), b"server shutdown");
    let _ = control_task.await;
    Ok(())
}

async fn run_client(
    server_addr: SocketAddr,
    fingerprint: String,
    target_id: String,
    access_password: String,
    display_name: Option<String>,
) -> Result<()> {
    let client = bind_client(SocketAddr::from(([0, 0, 0, 0], 0)), fingerprint).await?;
    let connection = client.connect(server_addr, "localhost").await?;

    let session_state = Arc::new(SessionStateMachine::new());
    session_state.transition(SessionState::Authenticating)?;

    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .context("failed to open control stream")?;

    send_message(
        &mut control_send,
        &ControlMessage::Hello {
            role: "client".to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await?;

    let requester_id = display_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "nexus-client".to_string())
        });

    send_message(
        &mut control_send,
        &ControlMessage::AuthRequest {
            requester_id,
            target_id,
            password: access_password,
        },
    )
    .await?;

    wait_for_auth_result(&mut control_recv).await?;
    session_state.transition(SessionState::PendingConsent)?;

    wait_for_session_consent(&mut control_recv).await?;
    session_state.transition(SessionState::Active)?;

    let (viewer_frame_tx, mut viewer_input_rx) =
        spawn_remote_viewer("NexusP2P - Remote Session [Active]")?;

    let session_state_for_input = Arc::clone(&session_state);
    let input_task = tokio::spawn(async move {
        while let Some(event) = viewer_input_rx.recv().await {
            if !session_state_for_input.is_active() {
                error!(
                    state = ?session_state_for_input.state(),
                    "SECURITY: blocked outbound input event while session not active"
                );
                continue;
            }

            let message = match event {
                ViewerInputEvent::MouseMove { x_norm, y_norm } => {
                    ControlMessage::SimulatedMouseMove { x_norm, y_norm }
                }
                ViewerInputEvent::Keyboard {
                    virtual_key,
                    pressed,
                } => ControlMessage::SimulatedKeyEvent {
                    virtual_key,
                    pressed,
                },
            };

            if let Err(error) = send_message(&mut control_send, &message).await {
                warn!(?error, "failed to forward viewer input event");
                break;
            }
        }
    });

    let ack_task = tokio::spawn(async move {
        loop {
            match recv_message::<ControlMessage>(&mut control_recv).await {
                Ok(ControlMessage::Ack(text)) => {
                    info!(%text, "received server acknowledgement");
                }
                Ok(message) => {
                    info!(?message, "received control message");
                }
                Err(error) => {
                    info!(?error, "control stream ended");
                    break;
                }
            }
        }
    });

    let mut frame_recv = connection
        .accept_uni()
        .await
        .context("server did not open a frame stream")?;

    loop {
        tokio::select! {
            packet = recv_message::<FramePacket>(&mut frame_recv) => {
                match packet {
                    Ok(packet) => {
                        if !session_state.is_active() {
                            error!(
                                state = ?session_state.state(),
                                sequence = packet.sequence,
                                "SECURITY: blocked inbound frame while session not active"
                            );
                            continue;
                        }

                        let Some(expected) = packet.checked_buffer_len() else {
                            warn!(
                                sequence = packet.sequence,
                                width = packet.width,
                                height = packet.height,
                                stride = packet.stride,
                                "dropping frame with overflowed buffer size"
                            );
                            continue;
                        };

                        if packet.pixels.len() != expected {
                            warn!(
                                sequence = packet.sequence,
                                bytes = packet.pixels.len(),
                                expected,
                                "dropping frame with invalid payload size"
                            );
                            continue;
                        }

                        info!(
                            sequence = packet.sequence,
                            width = packet.width,
                            height = packet.height,
                            bytes = packet.pixels.len(),
                            "received frame"
                        );

                        let frame = ViewerFrame {
                            width: packet.width,
                            height: packet.height,
                            stride: packet.stride,
                            pixels: packet.pixels,
                        };

                        if viewer_frame_tx.send(frame).is_err() {
                            info!("viewer closed, ending client frame loop");
                            break;
                        }
                    }
                    Err(error) => {
                        info!(?error, "frame stream ended");
                        break;
                    }
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                info!("client shutdown requested");
                break;
            }
        }
    }

    let _ = session_state.transition(SessionState::Terminated);
    connection.close(VarInt::from_u32(0), b"client shutdown");
    input_task.abort();
    let _ = input_task.await;
    ack_task.abort();
    let _ = ack_task.await;
    Ok(())
}

async fn wait_for_auth_request(control_recv: &mut RecvStream) -> Result<IncomingAuth> {
    let mut saw_hello = false;

    loop {
        match recv_message::<ControlMessage>(control_recv).await {
            Ok(ControlMessage::Hello {
                role,
                protocol_version,
            }) => {
                info!(%role, protocol_version, "received client hello");
                if protocol_version != PROTOCOL_VERSION {
                    warn!(
                        protocol_version,
                        expected = PROTOCOL_VERSION,
                        "client protocol version mismatch"
                    );
                }
                saw_hello = true;
            }
            Ok(ControlMessage::AuthRequest {
                requester_id,
                target_id,
                password,
            }) => {
                if !saw_hello {
                    warn!("client sent auth request before hello");
                }
                return Ok(IncomingAuth {
                    requester_id,
                    target_id,
                    password,
                });
            }
            Ok(other) => {
                error!(
                    ?other,
                    "SECURITY: blocked unexpected packet before authentication"
                );
            }
            Err(error) => {
                return Err(error).context("failed while waiting for auth request");
            }
        }
    }
}

async fn wait_for_auth_result(control_recv: &mut RecvStream) -> Result<()> {
    loop {
        match recv_message::<ControlMessage>(control_recv).await {
            Ok(ControlMessage::AuthResult { success, message }) => {
                if success {
                    info!(%message, "authentication accepted by host");
                    return Ok(());
                }
                return Err(SecurityError::AuthenticationFailed)
                    .context(format!("host rejected credentials: {message}"));
            }
            Ok(other) => {
                error!(
                    ?other,
                    "SECURITY: blocked unexpected packet while waiting for auth result"
                );
            }
            Err(error) => {
                return Err(error).context("failed while waiting for auth result");
            }
        }
    }
}

async fn wait_for_session_consent(control_recv: &mut RecvStream) -> Result<()> {
    loop {
        match recv_message::<ControlMessage>(control_recv).await {
            Ok(ControlMessage::SessionConsent { approved }) => {
                if approved {
                    info!("host approved session request");
                    return Ok(());
                }
                return Err(SecurityError::UserConsentDenied).context("host denied user consent");
            }
            Ok(ControlMessage::Ack(text)) => {
                info!(%text, "received server acknowledgement while waiting for consent");
            }
            Ok(other) => {
                error!(
                    ?other,
                    "SECURITY: blocked unexpected packet while waiting for consent"
                );
            }
            Err(error) => {
                return Err(error).context("failed while waiting for session consent");
            }
        }
    }
}

async fn prompt_for_host_consent(requester_id: &str) -> Result<bool> {
    if let Ok(value) = std::env::var("NEXUS_AUTO_CONSENT") {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "y") {
            warn!("NEXUS_AUTO_CONSENT enabled: auto-approving consent for this session");
            return Ok(true);
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "n") {
            warn!("NEXUS_AUTO_CONSENT enabled: auto-denying consent for this session");
            return Ok(false);
        }
    }

    let requester_id = requester_id.to_string();

    tokio::task::spawn_blocking(move || show_host_consent_dialog(&requester_id))
        .await
        .context("consent dialog task failed")?
}

async fn send_message<T: Serialize>(stream: &mut SendStream, value: &T) -> Result<()> {
    let payload = bincode::serialize(value).context("failed to encode message")?;
    if payload.len() > MAX_MESSAGE_BYTES {
        bail!(
            "encoded message exceeds max size: {} > {} bytes",
            payload.len(),
            MAX_MESSAGE_BYTES
        );
    }

    let len = u32::try_from(payload.len()).context("message too large")?;

    stream
        .write_all(&len.to_le_bytes())
        .await
        .context("failed to write message length")?;
    stream
        .write_all(&payload)
        .await
        .context("failed to write message payload")?;
    Ok(())
}

async fn recv_message<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0_u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("failed to read message length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        bail!(
            "incoming message exceeds max size: {} > {} bytes",
            len,
            MAX_MESSAGE_BYTES
        );
    }

    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("failed to read message payload")?;

    bincode::deserialize(&payload).context("failed to decode message")
}

fn apply_mouse_event(
    input: &InputController,
    x_norm: f32,
    y_norm: f32,
    inject_input: bool,
) -> Result<MousePreview> {
    if inject_input {
        input.inject_mouse_move(x_norm, y_norm)
    } else {
        input.preview_mouse_move(x_norm, y_norm)
    }
}

fn apply_keyboard_event(
    input: &InputController,
    virtual_key: u16,
    pressed: bool,
    inject_input: bool,
) -> Result<KeyboardPreview> {
    if inject_input {
        input.inject_virtual_key_event(virtual_key, pressed)
    } else {
        input.preview_virtual_key_event(virtual_key, pressed)
    }
}

async fn prompt_launch_mode_interactive() -> Result<LaunchMode> {
    tokio::task::spawn_blocking(prompt_launch_mode_interactive_blocking)
        .await
        .context("interactive launcher task failed")?
}

fn prompt_launch_mode_interactive_blocking() -> Result<LaunchMode> {
    println!("NexusP2P Interactive Gateway");
    println!("Choose mode:");
    println!("  1) Host session (Server)");
    println!("  2) Connect to host (Client)");

    let mode = loop {
        let value = prompt_line("Select option [1/2]: ")?;
        match value.trim() {
            "1" => break 1_u8,
            "2" => break 2_u8,
            _ => {
                println!("Invalid choice. Enter 1 or 2.");
            }
        }
    };

    if mode == 1 {
        let port = prompt_u16_with_default("Server port", 5000)?;
        let fps = prompt_u16_with_default("Capture FPS (1-60)", DEFAULT_FPS)?;
        let inject_input = prompt_yes_no_with_default("Enable host input injection", false)?;
        let default_advertise = default_advertise_addr(port);
        let advertise_addr = prompt_socketaddr_with_default(
            "Advertised address for clients",
            default_advertise,
        )?;

        return Ok(LaunchMode::Server {
            port,
            fps,
            inject_input,
            advertise_addr: Some(advertise_addr),
        });
    }

    let access_id = prompt_non_empty("Target Access ID: ")?;
    let parsed_access_id =
        parse_access_id(&access_id).context("invalid access ID provided in interactive mode")?;

    let access_password = prompt_non_empty("Target Access Password (6 digits): ")?;
    let display_name = prompt_line("Your display name (optional): ")?;
    let display_name = if display_name.trim().is_empty() {
        None
    } else {
        Some(display_name.trim().to_string())
    };

    Ok(LaunchMode::Client {
        server_addr: parsed_access_id.server_addr,
        fingerprint: parsed_access_id.fingerprint,
        target_id: parsed_access_id.target_id,
        access_password,
        display_name,
    })
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("failed to flush prompt")?;

    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .context("failed to read user input")?;
    Ok(value.trim().to_string())
}

fn prompt_non_empty(prompt: &str) -> Result<String> {
    loop {
        let value = prompt_line(prompt)?;
        if !value.trim().is_empty() {
            return Ok(value);
        }
        println!("Value cannot be empty.");
    }
}

fn prompt_u16_with_default(prompt: &str, default: u16) -> Result<u16> {
    loop {
        let value = prompt_line(&format!("{prompt} [{default}]: "))?;
        if value.is_empty() {
            return Ok(default);
        }

        match value.parse::<u16>() {
            Ok(parsed) => return Ok(parsed),
            Err(error) => println!("Invalid number: {error}"),
        }
    }
}

fn prompt_socketaddr_with_default(prompt: &str, default: SocketAddr) -> Result<SocketAddr> {
    loop {
        let value = prompt_line(&format!("{prompt} [{default}]: "))?;
        if value.is_empty() {
            return Ok(default);
        }

        match value.parse::<SocketAddr>() {
            Ok(parsed) => return Ok(parsed),
            Err(error) => println!("Invalid socket address: {error}"),
        }
    }
}

fn prompt_yes_no_with_default(prompt: &str, default: bool) -> Result<bool> {
    let default_label = if default { "Y/n" } else { "y/N" };

    loop {
        let value = prompt_line(&format!("{prompt} [{default_label}]: "))?;
        if value.is_empty() {
            return Ok(default);
        }

        let normalized = value.to_ascii_lowercase();
        match normalized.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please enter yes or no."),
        }
    }
}

fn advertised_server_addr(bind_addr: SocketAddr, override_addr: Option<SocketAddr>) -> SocketAddr {
    if let Some(explicit) = override_addr {
        return explicit;
    }

    if bind_addr.ip().is_unspecified() {
        return default_advertise_addr(bind_addr.port());
    }

    bind_addr
}

fn default_advertise_addr(port: u16) -> SocketAddr {
    let ip = detect_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    SocketAddr::new(ip, port)
}

fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn build_access_id(server_addr: SocketAddr, fingerprint: &str, target_id: &str) -> Result<String> {
    let payload = AccessIdPayload {
        version: ACCESS_ID_VERSION,
        server_addr: server_addr.to_string(),
        fingerprint: normalize_fingerprint_hex(fingerprint)
            .context("failed to normalize fingerprint for access ID")?,
        target_id: target_id.to_string(),
    };

    let encoded = bincode::serialize(&payload).context("failed to serialize access ID payload")?;
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

fn parse_access_id(access_id: &str) -> Result<ParsedAccessId> {
    let decoded = URL_SAFE_NO_PAD
        .decode(access_id.trim())
        .context("failed to decode access ID")?;
    let payload: AccessIdPayload =
        bincode::deserialize(&decoded).context("failed to parse access ID payload")?;

    if payload.version != ACCESS_ID_VERSION {
        bail!(
            "unsupported access ID version: {} (expected {})",
            payload.version,
            ACCESS_ID_VERSION
        );
    }

    let server_addr = payload
        .server_addr
        .parse::<SocketAddr>()
        .context("access ID contains invalid server address")?;
    let fingerprint = normalize_fingerprint_hex(&payload.fingerprint)
        .context("access ID contains invalid fingerprint")?;
    let target_id = payload.target_id.trim().to_string();
    if target_id.is_empty() {
        bail!("access ID contains an empty target session ID");
    }

    Ok(ParsedAccessId {
        server_addr,
        fingerprint,
        target_id,
    })
}

#[cfg(test)]
mod tests {
    use super::{build_access_id, parse_access_id};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn access_id_roundtrip() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5000);
        let fingerprint =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let target_id = "a1b2c3d4e5f6";

        let token = build_access_id(server_addr, fingerprint, target_id).expect("build access ID");
        let parsed = parse_access_id(&token).expect("parse access ID");

        assert_eq!(parsed.server_addr, server_addr);
        assert_eq!(parsed.fingerprint, fingerprint);
        assert_eq!(parsed.target_id, target_id);
    }

    #[test]
    fn parse_access_id_rejects_invalid_data() {
        assert!(parse_access_id("invalid-token").is_err());
    }
}
