#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::{anyhow, bail, Context, Result};
use arboard::Clipboard;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use eframe::egui;
use egui::{Color32, ColorImage, RichText, Rounding, Stroke, TextureHandle, TextureOptions};
use nexus_core::{
    ControlMessage, FramePacket, SecurityError, SessionCredentials, SessionState,
    SessionStateMachine,
};
use nexus_display::{spawn_remote_viewer, ScreenCapturer, ViewerFrame, ViewerInputEvent};
use nexus_input::{
    InputController, KeyboardPreview, MousePreview, SessionState as InputSessionState,
};
use nexus_network::{
    bind_client, bind_server, normalize_fingerprint_hex,
    build_pinned_rustls_client_config,
    NetworkTopology, run_diagnostics,
};
use qrcode_generator::QrCodeEcc;
use quinn::{RecvStream, SendStream, VarInt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use bip39::{Language, Mnemonic};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tracing::{error, info, warn};
#[cfg(target_os = "windows")]
use winreg::enums::HKEY_CURRENT_USER;
#[cfg(target_os = "windows")]
use winreg::RegKey;

const PROTOCOL_VERSION: u16 = 1;
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_PORT: u16 = 0;
const DEFAULT_FPS: u16 = 30;
const MIN_FPS: u16 = 1;
const MAX_FPS: u16 = 60;
const ACCESS_ID_VERSION: u8 = 1;
const UI_REPAINT_MS: u64 = 16;
const DEEP_LINK_PREFIX: &str = "nexus://connect";

const CONNECTION_PAYLOAD_VERSION: u8 = 1;
const CONNECTION_PAYLOAD_FAMILY_IPV4: u8 = 4;
const CONNECTION_PAYLOAD_BYTES: usize = 32;
const CONNECTION_PAYLOAD_HEADER_BYTES: usize = 2;
const CONNECTION_PAYLOAD_IPV4_BYTES: usize = 4;
const CONNECTION_PAYLOAD_PORT_BYTES: usize = 2;
const CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES: usize = 16;
const CONNECTION_PAYLOAD_TARGET_ID_BYTES: usize = 6;
const CONNECTION_PAYLOAD_USED_BYTES: usize = CONNECTION_PAYLOAD_HEADER_BYTES
    + CONNECTION_PAYLOAD_IPV4_BYTES
    + CONNECTION_PAYLOAD_PORT_BYTES
    + CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES
    + CONNECTION_PAYLOAD_TARGET_ID_BYTES;
const CONNECTION_PAYLOAD_RESERVED_BYTES: usize =
    CONNECTION_PAYLOAD_BYTES - CONNECTION_PAYLOAD_USED_BYTES;

fn main() -> Result<()> {
    init_tracing();

    if let Err(error) = register_nexus_protocol_handler() {
        warn!(?error, "failed to register nexus protocol handler");
    }

    let launch_connection_seed = parse_launch_connection_seed();

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name("nexus-runtime")
        .build()
        .context("failed to create Tokio runtime")?;

    let (runtime_cmd_tx, runtime_cmd_rx) = mpsc::channel::<RuntimeCommand>(32);
    let (runtime_event_tx, runtime_event_rx) = mpsc::channel::<RuntimeEvent>(256);
    let ui_bridge = Arc::new(UiBridge::default());

    runtime.spawn(runtime_dispatch_loop(
        runtime_cmd_rx,
        runtime_event_tx,
        Arc::clone(&ui_bridge),
    ));

    let mut runtime_event_rx_slot = Some(runtime_event_rx);
    let mut runtime_cmd_tx_slot = Some(runtime_cmd_tx);
    let mut ui_bridge_slot = Some(ui_bridge);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NexusP2P Access Hub",
        native_options,
        Box::new(move |cc| {
            let app = NexusGuiApp::new(
                cc,
                runtime_cmd_tx_slot.take().expect("runtime command sender missing"),
                runtime_event_rx_slot
                    .take()
                    .expect("runtime event receiver missing"),
                ui_bridge_slot.take().expect("UI bridge missing"),
                launch_connection_seed.clone(),
                runtime.handle().clone(),
            );
            Box::new(app)
        }),
    )
    .map_err(|error| anyhow!("failed to launch desktop UI: {error}"))?;

    Ok(())
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,quinn=warn".to_string());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessIdPayload {
    version: u8,
    server_addr: String,
    fingerprint: String,
    target_id: String,
    tcp_port: Option<u16>,
}

#[derive(Debug, Clone)]
struct ParsedAccessId {
    server_addr: SocketAddr,
    fingerprint: String,
    target_id: String,
    tcp_port: Option<u16>,
}

#[derive(Debug, Clone)]
struct IncomingAuth {
    requester_id: String,
    target_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
enum TransportMode {
    #[default]
    AutoSelect,
    ForceQuicP2p,
    ForceHttpsTcp,
}

#[derive(Debug, Clone)]
struct HostRuntimeConfig {
    port: u16,
    fps: u16,
    inject_input: bool,
    advertise_addr: Option<SocketAddr>,
    transport_mode: TransportMode,
}

#[derive(Debug)]
enum RuntimeCommand {
    StartHosting(HostRuntimeConfig),
    ConnectWithAccessId {
        access_id: String,
        display_name: Option<String>,
        transport_mode: TransportMode,
    },
    RunDiagnostics,
}

#[derive(Debug)]
enum RuntimeEvent {
    HostReady {
        advertised_addr: SocketAddr,
        fingerprint: String,
        session_id: String,
        access_id: String,
        fps: u16,
        inject_input: bool,
    },
    IncomingSession {
        remote_addr: SocketAddr,
        requester_id: String,
        target_session: String,
    },
    ClientPermissionRequested {
        server_addr: SocketAddr,
        session_id: String,
    },
    HostConsentRequested {
        requester_id: String,
        remote_addr: SocketAddr,
        target_session: String,
    },
    HostLifecycle {
        running: bool,
    },
    ClientLifecycle {
        running: bool,
    },
    SessionStatus(String),
    DiagnosticsCompleted {
        topology: NetworkTopology,
        public_addr: Option<SocketAddr>,
    },
    ConnectionEstablished {
        protocol: String,
        local_addr: SocketAddr,
        latency_ms: u128,
    },
    Error(String),
}

#[derive(Default)]
struct UiBridge {
    pending_client_permission_sender: Mutex<Option<oneshot::Sender<bool>>>,
    pending_host_consent_sender: Mutex<Option<oneshot::Sender<bool>>>,
    client_punch_addr: Mutex<Option<SocketAddr>>,
}

impl UiBridge {
    fn install_client_permission_sender(&self, sender: oneshot::Sender<bool>) -> Result<()> {
        let mut guard = self
            .pending_client_permission_sender
            .lock()
            .map_err(|_| anyhow!("client permission bridge lock poisoned"))?;

        if guard.is_some() {
            bail!("a client permission request is already pending")
        }

        *guard = Some(sender);
        Ok(())
    }

    fn respond_client_permission(&self, approved: bool) -> Result<()> {
        let mut guard = self
            .pending_client_permission_sender
            .lock()
            .map_err(|_| anyhow!("client permission bridge lock poisoned"))?;

        match guard.take() {
            Some(sender) => sender
                .send(approved)
                .map_err(|_| anyhow!("failed to send client permission decision")),
            None => Err(anyhow!("no pending client permission request")),
        }
    }

    fn clear_client_permission_sender(&self) {
        if let Ok(mut guard) = self.pending_client_permission_sender.lock() {
            let _ = guard.take();
        }
    }

    fn install_host_consent_sender(&self, sender: oneshot::Sender<bool>) -> Result<()> {
        let mut guard = self
            .pending_host_consent_sender
            .lock()
            .map_err(|_| anyhow!("host consent bridge lock poisoned"))?;

        if guard.is_some() {
            bail!("a host consent request is already pending")
        }

        *guard = Some(sender);
        Ok(())
    }

    fn respond_host_consent(&self, approved: bool) -> Result<()> {
        let mut guard = self
            .pending_host_consent_sender
            .lock()
            .map_err(|_| anyhow!("host consent bridge lock poisoned"))?;

        match guard.take() {
            Some(sender) => sender
                .send(approved)
                .map_err(|_| anyhow!("failed to send host consent decision")),
            None => Err(anyhow!("no pending host consent request")),
        }
    }

    fn clear_host_consent_sender(&self) {
        if let Ok(mut guard) = self.pending_host_consent_sender.lock() {
            let _ = guard.take();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    HostMode,
    ClientMode,
}

#[derive(Debug, Clone)]
struct PermissionPrompt {
    server_addr: SocketAddr,
    session_id: String,
}

#[derive(Debug, Clone)]
struct HostConsentPrompt {
    requester_id: String,
    remote_addr: SocketAddr,
    target_session: String,
}

struct NexusGuiApp {
    active_tab: ActiveTab,
    access_id_input: String,
    generated_access_id: Option<String>,
    qr_code_texture: Option<TextureHandle>,
    copied_notice_until: Option<Instant>,
    pending_auto_connect: bool,

    host_port: u16,
    host_fps: u16,
    host_inject_input: bool,
    host_advertise_addr_input: String,

    client_display_name: String,
    pending_client_permission: Option<PermissionPrompt>,
    pending_host_consent: Option<HostConsentPrompt>,

    runtime_cmd_tx: mpsc::Sender<RuntimeCommand>,
    runtime_event_rx: mpsc::Receiver<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,

    host_running: bool,
    client_running: bool,
    status_message: String,
    session_logs: VecDeque<String>,
    detected_public_addr: Arc<Mutex<Option<SocketAddr>>>,
    detecting_public_ip: Arc<AtomicBool>,
    _runtime_handle: tokio::runtime::Handle,
    has_auto_hosted: bool,
    client_punch_addr_input: String,
    client_public_addr_display: String,

    host_transport_mode: TransportMode,
    network_topology: NetworkTopology,
    telemetry_protocol: String,
    telemetry_local_addr: String,
    telemetry_latency_ms: Option<u128>,
}

impl NexusGuiApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        runtime_cmd_tx: mpsc::Sender<RuntimeCommand>,
        runtime_event_rx: mpsc::Receiver<RuntimeEvent>,
        ui_bridge: Arc<UiBridge>,
        launch_connection_seed: Option<String>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        apply_modern_theme(&cc.egui_ctx);

        let host_port = DEFAULT_PORT;
        let default_advertise = default_advertise_addr(host_port).to_string();
        let pending_auto_connect = launch_connection_seed
            .as_ref()
            .map(|seed| parse_connection_seed(seed).is_ok())
            .unwrap_or(false);

        // Auto-start hosting immediately on startup if not in client mode
        if launch_connection_seed.is_none() {
            let command = RuntimeCommand::StartHosting(HostRuntimeConfig {
                port: host_port,
                fps: DEFAULT_FPS,
                inject_input: false,
                advertise_addr: None,
                transport_mode: TransportMode::AutoSelect,
            });
            let _ = runtime_cmd_tx.try_send(command);
        }

        let detected_public_addr = Arc::new(Mutex::new(None));
        let detecting_public_ip = Arc::new(AtomicBool::new(true));

        Self {
            active_tab: if launch_connection_seed.is_some() {
                ActiveTab::ClientMode
            } else {
                ActiveTab::HostMode
            },
            access_id_input: launch_connection_seed.unwrap_or_default(),
            generated_access_id: None,
            qr_code_texture: None,
            copied_notice_until: None,
            pending_auto_connect,
            host_port,
            host_fps: DEFAULT_FPS,
            host_inject_input: false,
            host_advertise_addr_input: default_advertise,
            client_display_name: String::new(),
            pending_client_permission: None,
            pending_host_consent: None,
            runtime_cmd_tx,
            runtime_event_rx,
            ui_bridge,
            host_running: false,
            client_running: false,
            status_message: "Ready".to_string(),
            session_logs: VecDeque::with_capacity(200),
            detected_public_addr,
            detecting_public_ip,
            _runtime_handle: runtime_handle,
            has_auto_hosted: true, // Mark auto-hosted as true since we spawned it above
            client_punch_addr_input: String::new(),
            client_public_addr_display: String::new(),
            host_transport_mode: TransportMode::AutoSelect,
            network_topology: NetworkTopology::Undetermined,
            telemetry_protocol: "None".to_string(),
            telemetry_local_addr: "Not bound".to_string(),
            telemetry_latency_ms: None,
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status_message = status.into();
    }

    fn push_log(&mut self, line: impl Into<String>) {
        if self.session_logs.len() >= 150 {
            let _ = self.session_logs.pop_front();
        }
        self.session_logs.push_back(line.into());
    }

    fn poll_runtime_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.runtime_event_rx.try_recv() {
            match event {
                RuntimeEvent::HostReady {
                    advertised_addr,
                    fingerprint,
                    session_id,
                    access_id,
                    fps,
                    inject_input,
                } => {
                    self.generated_access_id = Some(access_id.clone());
                    self.host_advertise_addr_input = advertised_addr.to_string();
                    self.client_public_addr_display = advertised_addr.to_string();
                    self.set_status("Host is ready and waiting for incoming sessions");
                    self.push_log(format!(
                        "HOST READY endpoint={} session_id={} fps={} mode={}",
                        advertised_addr,
                        session_id,
                        fps,
                        if inject_input { "inject" } else { "preview" }
                    ));
                    self.push_log(format!("HOST CERT SHA256 {}", fingerprint));
                    if let Err(error) = self.rebuild_qr_texture(ctx) {
                        self.push_log(format!("QR generation failed: {error}"));
                    }
                }
                RuntimeEvent::IncomingSession {
                    remote_addr,
                    requester_id,
                    target_session,
                } => {
                    self.push_log(format!(
                        "INCOMING SESSION requester={} remote={} target_id={}",
                        requester_id, remote_addr, target_session
                    ));
                    self.set_status("Incoming session detected");
                }
                RuntimeEvent::ClientPermissionRequested {
                    server_addr,
                    session_id,
                } => {
                    self.pending_client_permission = Some(PermissionPrompt {
                        server_addr,
                        session_id,
                    });
                    self.set_status("Server requested client permission");
                }
                RuntimeEvent::HostConsentRequested {
                    requester_id,
                    remote_addr,
                    target_session,
                } => {
                    self.pending_host_consent = Some(HostConsentPrompt {
                        requester_id,
                        remote_addr,
                        target_session,
                    });
                    self.set_status("Awaiting host-side consent");
                }
                RuntimeEvent::HostLifecycle { running } => {
                    self.host_running = running;
                    if !running {
                        self.pending_host_consent = None;
                        self.ui_bridge.clear_host_consent_sender();
                        self.push_log("Host task finished".to_string());
                    }
                }
                RuntimeEvent::ClientLifecycle { running } => {
                    self.client_running = running;
                    if !running {
                        self.pending_client_permission = None;
                        self.ui_bridge.clear_client_permission_sender();
                        self.push_log("Client task finished".to_string());
                    }
                }
                RuntimeEvent::SessionStatus(text) => {
                    self.set_status(text.clone());
                    self.push_log(text);
                }
                RuntimeEvent::DiagnosticsCompleted { topology, public_addr } => {
                    self.network_topology = topology.clone();
                    if let Some(addr) = public_addr {
                        self.host_advertise_addr_input = addr.to_string();
                        self.client_public_addr_display = addr.to_string();
                    }
                    self.detecting_public_ip.store(false, Ordering::Relaxed);
                    self.push_log(format!("Network diagnostic completed: {:?}", topology));
                }
                RuntimeEvent::ConnectionEstablished { protocol, local_addr, latency_ms } => {
                    self.telemetry_protocol = protocol;
                    self.telemetry_local_addr = local_addr.to_string();
                    self.telemetry_latency_ms = Some(latency_ms);
                    self.push_log(format!("Connection established over {} at local socket {}", self.telemetry_protocol, self.telemetry_local_addr));
                }
                RuntimeEvent::Error(error) => {
                    self.set_status("Operation failed");
                    self.push_log(format!("ERROR {error}"));
                }
            }
        }
    }

    fn rebuild_qr_texture(&mut self, ctx: &egui::Context) -> Result<()> {
        let access_id = self
            .generated_access_id
            .as_deref()
            .context("missing access ID for QR generation")?;

        let image = build_qr_color_image(access_id)?;

        if let Some(texture) = self.qr_code_texture.as_mut() {
            texture.set(image, TextureOptions::NEAREST);
        } else {
            self.qr_code_texture = Some(ctx.load_texture(
                "host_access_qr",
                image,
                TextureOptions::NEAREST,
            ));
        }

        Ok(())
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("NEXUSP2P")
                        .size(30.0)
                        .strong()
                        .color(Color32::from_rgb(234, 244, 255)),
                );
                ui.label(
                    RichText::new("Secure Access Exchange and Session Orchestration")
                        .size(13.5)
                        .color(Color32::from_rgb(164, 183, 206)),
                );
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                status_chip(
                    ui,
                    if self.client_running {
                        "CLIENT ACTIVE"
                    } else {
                        "CLIENT READY"
                    },
                    if self.client_running {
                        Color32::from_rgb(38, 123, 92)
                    } else {
                        Color32::from_rgb(59, 74, 96)
                    },
                );
                status_chip(
                    ui,
                    if self.host_running {
                        "🟢 LIVE & AVAILABLE"
                    } else {
                        "⚪ STANDBY"
                    },
                    if self.host_running {
                        Color32::from_rgb(33, 115, 70)
                    } else {
                        Color32::from_rgb(65, 84, 110)
                    },
                );
                match self.network_topology {
                    NetworkTopology::Undetermined => {
                        status_chip(
                            ui,
                            "⚪ Network Status: Detecting...",
                            Color32::from_rgb(97, 107, 124),
                        );
                    }
                    NetworkTopology::OpenInternet => {
                        status_chip(
                            ui,
                            "🟢 Network Status: Excellent (Open Internet)",
                            Color32::from_rgb(33, 115, 70),
                        );
                    }
                    NetworkTopology::ConeNatFriendly => {
                        status_chip(
                            ui,
                            "🟢 Network Status: Excellent (P2P Direct)",
                            Color32::from_rgb(33, 115, 70),
                        );
                    }
                    NetworkTopology::SymmetricNatRestrictive => {
                        status_chip(
                            ui,
                            "🟠 Network Status: Restrictive (Symmetric NAT - TCP Recommended)",
                            Color32::from_rgb(217, 119, 6),
                        );
                    }
                    NetworkTopology::UdpBlockedStrict => {
                        status_chip(
                            ui,
                            "🔴 Network Status: Blocked UDP (HTTPS Fallback Enforced)",
                            Color32::from_rgb(198, 40, 40),
                        );
                    }
                }
            });
        });

        ui.add_space(12.0);

        ui.horizontal(|ui| {
            let host_selected = self.active_tab == ActiveTab::HostMode;
            let client_selected = self.active_tab == ActiveTab::ClientMode;

            if ui
                .add_sized(
                    [180.0, 38.0],
                    egui::Button::new(RichText::new("Host Mode").size(15.5).strong())
                        .rounding(Rounding::same(12.0))
                        .fill(if host_selected {
                            Color32::from_rgb(53, 123, 171)
                        } else {
                            Color32::from_rgb(30, 44, 67)
                        }),
                )
                .clicked()
            {
                self.active_tab = ActiveTab::HostMode;
            }

            if ui
                .add_sized(
                    [180.0, 38.0],
                    egui::Button::new(RichText::new("Client Mode").size(15.5).strong())
                        .rounding(Rounding::same(12.0))
                        .fill(if client_selected {
                            Color32::from_rgb(53, 123, 171)
                        } else {
                            Color32::from_rgb(30, 44, 67)
                        }),
                )
                .clicked()
            {
                self.active_tab = ActiveTab::ClientMode;
            }
        });
    }

    fn build_host_connection_bundle(&self) -> Result<(String, String, String)> {
        let access_id = self
            .generated_access_id
            .as_deref()
            .context("missing access ID for connection bundle")?;

        let parsed = parse_connection_seed(access_id)
            .context("failed to parse generated access ID as connection seed")?;
        let payload = build_connection_payload_bytes(
            parsed.server_addr,
            &parsed.fingerprint,
            &parsed.target_id,
            parsed.tcp_port,
        )?;

        let seed = URL_SAFE_NO_PAD.encode(&payload);
        let mnemonic = encode_connection_seed_mnemonic(&payload)?;
        let deep_link = build_connection_deep_link(&seed);

        Ok((seed, mnemonic, deep_link))
    }

    fn draw_host_controls_card(&mut self, ui: &mut egui::Ui) {
        card(
            ui,
            "Host Session Controls",
            "Low-latency endpoint and capture configuration",
            |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.add(
                            egui::DragValue::new(&mut self.host_port)
                                .clamp_range(0..=65535)
                                .speed(1),
                        );

                        ui.add_space(20.0);
                        ui.label("Capture FPS:");
                        ui.add(egui::Slider::new(&mut self.host_fps, MIN_FPS..=MAX_FPS));
                    });

                    ui.add_space(8.0);
                    ui.checkbox(&mut self.host_inject_input, "Enable host input injection");

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Transport Mode:");
                        egui::ComboBox::from_id_source("host_transport_mode_combo")
                            .selected_text(match self.host_transport_mode {
                                TransportMode::AutoSelect => "Auto-Select",
                                TransportMode::ForceQuicP2p => "Force QUIC Direct P2P",
                                TransportMode::ForceHttpsTcp => "Force HTTPS-TCP Fallback (Port 443)",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::AutoSelect, "Auto-Select");
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::ForceQuicP2p, "Force QUIC Direct P2P");
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::ForceHttpsTcp, "Force HTTPS-TCP Fallback (Port 443)");
                            });
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Advertised Address:");
                        ui.add_sized(
                            [ui.available_width() - 160.0, 24.0],
                            egui::TextEdit::singleline(&mut self.host_advertise_addr_input)
                                .hint_text("e.g. 12.34.56.78:5000"),
                        );

                        let detect_btn_label = if self.detecting_public_ip.load(Ordering::Relaxed) {
                            "Detecting..."
                        } else {
                            "Run Diagnostics"
                        };

                        if ui
                            .add_enabled(
                                !self.detecting_public_ip.load(Ordering::Relaxed),
                                egui::Button::new(detect_btn_label),
                            )
                            .clicked()
                        {
                            self.detecting_public_ip.store(true, Ordering::Relaxed);
                            let _ = self.runtime_cmd_tx.try_send(RuntimeCommand::RunDiagnostics);
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Client Address (for Hole Punching):");
                        ui.add_sized(
                            [ui.available_width(), 24.0],
                            egui::TextEdit::singleline(&mut self.client_punch_addr_input)
                                .hint_text("e.g. 12.34.56.78:54321 (optional)"),
                        );
                    });

                    ui.add_space(12.0);

                    let start_button_label = if self.host_running {
                        "Hosting..."
                    } else {
                        "Start Hosting"
                    };

                    if ui
                        .add_sized(
                            [ui.available_width(), 32.0],
                            egui::Button::new(start_button_label)
                                .rounding(Rounding::same(10.0))
                                .fill(Color32::from_rgb(42, 132, 92)),
                        )
                        .clicked()
                    {
                        self.start_hosting_clicked();
                    }
                });
            },
        );
    }

    fn draw_oob_exchange_card(&mut self, ui: &mut egui::Ui) {
        card(
            ui,
            "Out-of-Band Access Exchange",
            "Credentials, connection files, and QR workflows",
            |ui| {
                if self.generated_access_id.is_some() {
                    let mut export_seed = String::new();
                    let mut deep_link = String::new();
                    let mut mnemonic = String::new();
                    let mut show_mnemonic = false;

                    if let Ok((seed, mnem, link)) = self.build_host_connection_bundle() {
                        export_seed = seed;
                        deep_link = link;
                        mnemonic = mnem;
                        show_mnemonic = true;
                    } else if let Some(legacy) = &self.generated_access_id {
                        export_seed = legacy.clone();
                    }

                    ui.vertical(|ui| {
                        ui.label("Connection Seed (Base64):");
                        let mut seed_display = export_seed.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut seed_display)
                                .desired_rows(2)
                                .interactive(false)
                                .code_editor(),
                        );

                        if show_mnemonic {
                            ui.add_space(4.0);
                            ui.label("Mnemonic Phrase (24 Words):");
                            let mut mnem_display = mnemonic.clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut mnem_display)
                                    .desired_rows(3)
                                    .interactive(false)
                                    .code_editor(),
                            );
                        }

                        ui.add_space(8.0);

                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add(
                                    egui::Button::new("Copy Seed")
                                        .rounding(Rounding::same(10.0))
                                        .fill(Color32::from_rgb(60, 108, 171)),
                                )
                                .clicked()
                            {
                                match copy_text_to_clipboard(&export_seed) {
                                    Ok(()) => {
                                        self.copied_notice_until =
                                            Some(Instant::now() + Duration::from_secs(2));
                                        self.set_status("Connection seed copied to clipboard");
                                    }
                                    Err(error) => {
                                        self.push_log(format!("Clipboard copy failed: {error}"));
                                    }
                                }
                            }

                            if show_mnemonic {
                                if ui
                                    .add(
                                        egui::Button::new("Copy Mnemonic")
                                            .rounding(Rounding::same(10.0))
                                            .fill(Color32::from_rgb(48, 117, 173)),
                                    )
                                    .clicked()
                                {
                                    match copy_text_to_clipboard(&mnemonic) {
                                        Ok(()) => {
                                            self.copied_notice_until =
                                                Some(Instant::now() + Duration::from_secs(2));
                                            self.set_status("Mnemonic copied to clipboard");
                                        }
                                        Err(error) => {
                                            self.push_log(format!("Clipboard copy failed: {error}"));
                                        }
                                    }
                                }
                            }

                            if !deep_link.is_empty() {
                                if ui
                                    .add(
                                        egui::Button::new("Copy Deep Link")
                                            .rounding(Rounding::same(10.0))
                                            .fill(Color32::from_rgb(80, 91, 128)),
                                    )
                                    .clicked()
                                {
                                    match copy_text_to_clipboard(&deep_link) {
                                        Ok(()) => {
                                            self.copied_notice_until =
                                                Some(Instant::now() + Duration::from_secs(2));
                                            self.set_status("Deep link copied to clipboard");
                                        }
                                        Err(error) => {
                                            self.push_log(format!("Clipboard copy failed: {error}"));
                                        }
                                    }
                                }
                            }

                            if ui
                                .add(
                                    egui::Button::new("Save Connection File")
                                        .rounding(Rounding::same(10.0))
                                        .fill(Color32::from_rgb(80, 91, 128)),
                                )
                                .clicked()
                            {
                                match save_access_id_file(&export_seed) {
                                    Ok(path) => {
                                        self.set_status("Connection file exported successfully");
                                        self.push_log(format!("Saved access file to {}", path.display()));
                                    }
                                    Err(error) => {
                                        self.push_log(format!("Connection file export failed: {error}"));
                                    }
                                }
                            }

                            if ui
                                .add(
                                    egui::Button::new("Export QR PNG")
                                        .rounding(Rounding::same(10.0))
                                        .fill(Color32::from_rgb(68, 118, 173)),
                                )
                                .clicked()
                            {
                                match save_access_id_qr_png(&export_seed) {
                                    Ok(path) => {
                                        self.set_status("QR PNG exported successfully");
                                        self.push_log(format!("Saved QR PNG to {}", path.display()));
                                    }
                                    Err(error) => {
                                        self.push_log(format!("QR PNG export failed: {error}"));
                                    }
                                }
                            }
                        });

                        ui.add_space(10.0);

                        if let Some(texture) = &self.qr_code_texture {
                            ui.vertical_centered(|ui| {
                                let side = 240.0;
                                ui.image((texture.id(), egui::vec2(side, side)));
                            });
                        }
                    });
                } else {
                    ui.label(
                        RichText::new("Start hosting to generate credentials and QR code")
                            .color(Color32::from_rgb(176, 190, 207)),
                    );
                }
            },
        );
    }

    fn draw_client_request_card(&mut self, ui: &mut egui::Ui) {
        card(
            ui,
            "Client Access Request",
            "Import connection seed from text, file, or QR payload",
            |ui| {
                ui.vertical(|ui| {
                    ui.label("Connection Seed / Mnemonic Phrase / Deep Link:");
                    ui.add_sized(
                        [ui.available_width(), 80.0],
                        egui::TextEdit::multiline(&mut self.access_id_input)
                            .hint_text("Paste connection seed, mnemonic phrase, deep link, or legacy Access ID"),
                    );

                    if !self.client_public_addr_display.is_empty() {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("My Public UDP Address (share this with Host):").color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new(&self.client_public_addr_display).strong().color(Color32::from_rgb(230, 239, 251)));
                            if ui.button("Copy").clicked() {
                                if let Err(e) = copy_text_to_clipboard(&self.client_public_addr_display) {
                                    self.push_log(format!("Failed to copy public address: {}", e));
                                } else {
                                    self.set_status("Public UDP address copied to clipboard");
                                }
                            }
                        });
                    }

                    let suggestions = {
                        let current_text = &self.access_id_input;
                        if !current_text.is_empty() && !current_text.ends_with(' ') && !current_text.ends_with('\n') {
                            if let Some(last_word) = current_text.split_whitespace().last() {
                                let last_word_lower = last_word.to_lowercase();
                                let matches: Vec<String> = bip39::Language::English.word_list()
                                    .iter()
                                    .filter(|w| w.starts_with(&last_word_lower) && **w != last_word_lower)
                                    .take(5)
                                    .map(|s| s.to_string())
                                    .collect();

                                if !matches.is_empty() {
                                    Some((last_word.to_string(), matches))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    if let Some((last_word, matches)) = suggestions {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("Suggestions:").size(13.0).color(Color32::from_rgb(140, 160, 190)));
                            for word in matches {
                                if ui.add(egui::Button::new(RichText::new(&word).size(13.0)).rounding(Rounding::same(6.0))).clicked() {
                                    if let Some(pos) = self.access_id_input.rfind(&last_word) {
                                        self.access_id_input.replace_range(pos.., &format!("{} ", word));
                                    }
                                }
                            }
                        });
                    }

                    ui.add_space(8.0);

                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add(
                                egui::Button::new("Paste Clipboard")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(60, 108, 171)),
                            )
                            .clicked()
                        {
                            match paste_text_from_clipboard() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Seed pasted from clipboard");
                                }
                                Err(error) => {
                                    self.push_log(format!("Clipboard paste failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Load File")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(80, 91, 128)),
                            )
                            .clicked()
                        {
                            match load_access_id_file() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Seed loaded from file");
                                }
                                Err(error) => {
                                    self.push_log(format!("File load failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Load QR")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(93, 88, 132)),
                            )
                            .clicked()
                        {
                            match load_access_id_from_qr_file() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Seed decoded from QR image");
                                }
                                Err(error) => {
                                    self.push_log(format!("QR file decode failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Decode Clipboard QR")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(94, 79, 116)),
                            )
                            .clicked()
                        {
                            match load_access_id_from_clipboard_image() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Seed decoded from clipboard QR");
                                }
                                Err(error) => {
                                    self.push_log(format!("Clipboard QR decode failed: {error}"));
                                }
                            }
                        }
                    });

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Display Name:");
                        ui.add_sized(
                            [ui.available_width() - 100.0, 24.0],
                            egui::TextEdit::singleline(&mut self.client_display_name)
                                .hint_text("optional"),
                        );
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Transport Mode:");
                        egui::ComboBox::from_id_source("client_transport_mode_combo")
                            .selected_text(match self.host_transport_mode {
                                TransportMode::AutoSelect => "Auto-Select",
                                TransportMode::ForceQuicP2p => "Force QUIC Direct P2P",
                                TransportMode::ForceHttpsTcp => "Force HTTPS-TCP Fallback (Port 443)",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::AutoSelect, "Auto-Select");
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::ForceQuicP2p, "Force QUIC Direct P2P");
                                ui.selectable_value(&mut self.host_transport_mode, TransportMode::ForceHttpsTcp, "Force HTTPS-TCP Fallback (Port 443)");
                            });
                    });

                    ui.add_space(10.0);

                    let connect_label = if self.client_running {
                        "Connecting..."
                    } else {
                        "Connect"
                    };

                    if ui
                        .add_sized(
                            [ui.available_width(), 32.0],
                            egui::Button::new(connect_label)
                                .rounding(Rounding::same(10.0))
                                .fill(Color32::from_rgb(42, 132, 92)),
                        )
                        .clicked()
                    {
                        self.connect_clicked();
                    }
                });
            },
        );
    }

    fn draw_telemetry_card(&mut self, ui: &mut egui::Ui, title: &str, max_lines: usize) {
        card(
            ui,
            title,
            "Recent runtime, connection, and handshake events",
            |ui| {
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.label(RichText::new("Active Connection Parameters").strong().size(13.0));
                        ui.horizontal(|ui| {
                            ui.label("Protocol:");
                            ui.label(RichText::new(&self.telemetry_protocol).strong().color(Color32::from_rgb(95, 194, 242)));
                            ui.add_space(15.0);
                            ui.label("Local Socket:");
                            ui.label(RichText::new(&self.telemetry_local_addr).strong().color(Color32::from_rgb(230, 239, 251)));
                            ui.add_space(15.0);
                            ui.label("Latency:");
                            if let Some(latency) = self.telemetry_latency_ms {
                                ui.label(RichText::new(format!("{} ms", latency)).strong().color(Color32::from_rgb(46, 125, 50)));
                            } else {
                                ui.label(RichText::new("N/A").strong().color(Color32::from_rgb(140, 160, 190)));
                            }
                        });
                    });
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            for line in self.session_logs.iter().rev().take(max_lines) {
                                ui.label(RichText::new(line).size(12.5));
                            }
                        });
                });
            },
        );
    }

    fn draw_dashboard(&mut self, ui: &mut egui::Ui) {
        let screen_width = ui.ctx().screen_rect().width();
        if screen_width >= 1100.0 {
            ui.columns(2, |columns| {
                columns[0].vertical(|ui| {
                    self.draw_host_controls_card(ui);
                    ui.add_space(10.0);
                    self.draw_oob_exchange_card(ui);
                    ui.add_space(10.0);
                    self.draw_telemetry_card(ui, "Host Live Telemetry", 35);
                });

                columns[1].vertical(|ui| {
                    self.draw_client_request_card(ui);
                    ui.add_space(10.0);
                    self.draw_telemetry_card(ui, "Connection Telemetry", 35);
                });
            });
        } else {
            match self.active_tab {
                ActiveTab::HostMode => {
                    ui.vertical(|ui| {
                        self.draw_host_controls_card(ui);
                        ui.add_space(10.0);
                        self.draw_oob_exchange_card(ui);
                        ui.add_space(10.0);
                        self.draw_telemetry_card(ui, "Live Telemetry", 35);
                    });
                }
                ActiveTab::ClientMode => {
                    ui.vertical(|ui| {
                        self.draw_client_request_card(ui);
                        ui.add_space(10.0);
                        self.draw_telemetry_card(ui, "Connection Telemetry", 50);
                    });
                }
            }
        }
    }

    fn start_hosting_clicked(&mut self) {
        let advertise_addr = if self.host_advertise_addr_input.trim().is_empty() {
            None
        } else {
            match self.host_advertise_addr_input.trim().parse::<SocketAddr>() {
                Ok(parsed) => Some(parsed),
                Err(error) => {
                    self.push_log(format!("Invalid advertised address: {error}"));
                    return;
                }
            }
        };

        let command = RuntimeCommand::StartHosting(HostRuntimeConfig {
            port: self.host_port,
            fps: self.host_fps,
            inject_input: self.host_inject_input,
            advertise_addr,
            transport_mode: self.host_transport_mode,
        });

        match self.runtime_cmd_tx.try_send(command) {
            Ok(()) => {
                self.set_status("Starting host runtime...");
                self.host_running = true;
            }
            Err(error) => {
                self.push_log(format!("Failed to start host runtime: {error}"));
            }
        }
    }

    fn connect_clicked(&mut self) {
        let access_id = self.access_id_input.trim();
        if access_id.is_empty() {
            self.push_log("Access ID is required before connecting".to_string());
            return;
        }

        if let Err(error) = parse_connection_seed(access_id) {
            self.push_log(format!("Connection seed validation failed: {error}"));
            return;
        }

        let display_name = self
            .client_display_name
            .trim()
            .to_string();

        let command = RuntimeCommand::ConnectWithAccessId {
            access_id: access_id.to_string(),
            display_name: if display_name.is_empty() {
                None
            } else {
                Some(display_name)
            },
            transport_mode: self.host_transport_mode,
        };

        match self.runtime_cmd_tx.try_send(command) {
            Ok(()) => {
                self.set_status("Connecting to remote host...");
                self.client_running = true;
            }
            Err(error) => {
                self.push_log(format!("Failed to start client connection: {error}"));
            }
        }
    }

    fn draw_status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            status_chip(
                ui,
                if self.host_running { "🟢 LIVE - AVAILABLE FOR INCOMING SESSIONS" } else { "⚪ STANDBY" },
                if self.host_running {
                    Color32::from_rgb(33, 115, 70)
                } else {
                    Color32::from_rgb(66, 84, 107)
                },
            );

            status_chip(
                ui,
                if self.client_running {
                    "CLIENT RUNNING"
                } else {
                    "CLIENT STANDBY"
                },
                if self.client_running {
                    Color32::from_rgb(38, 123, 92)
                } else {
                    Color32::from_rgb(66, 84, 107)
                },
            );

            ui.add_space(10.0);
            ui.label(
                RichText::new(&self.status_message)
                    .color(Color32::from_rgb(230, 239, 251))
                    .size(13.0),
            );
        });
    }

    fn draw_copy_notice(&mut self, ctx: &egui::Context) {
        if let Some(until) = self.copied_notice_until {
            if Instant::now() <= until {
                egui::Window::new("copied_notice")
                    .title_bar(false)
                    .resizable(false)
                    .collapsible(false)
                    .fixed_pos(egui::pos2(18.0, 18.0))
                    .show(ctx, |ui| {
                        ui.label(
                            RichText::new("Copied to clipboard")
                                .strong()
                                .color(Color32::from_rgb(232, 243, 255)),
                        );
                    });
            } else {
                self.copied_notice_until = None;
            }
        }
    }

    fn draw_client_permission_prompt(&mut self, ctx: &egui::Context) {
        let Some(prompt) = self.pending_client_permission.clone() else {
            return;
        };

        egui::Window::new("Server Access Request")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Server Access Request")
                        .strong()
                        .size(18.0),
                );
                ui.add_space(6.0);
                ui.label(format!("Server: {}", prompt.server_addr));
                ui.label(format!("Session ID: {}", prompt.session_id));
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new("Deny").fill(Color32::from_rgb(128, 46, 57)))
                        .clicked()
                    {
                        match self.ui_bridge.respond_client_permission(false) {
                            Ok(()) => {
                                self.pending_client_permission = None;
                                self.set_status("Client denied server access request");
                            }
                            Err(error) => {
                                self.push_log(format!("Failed to send deny decision: {error}"));
                            }
                        }
                    }

                    if ui
                        .add(egui::Button::new("Approve").fill(Color32::from_rgb(44, 125, 83)))
                        .clicked()
                    {
                        match self.ui_bridge.respond_client_permission(true) {
                            Ok(()) => {
                                self.pending_client_permission = None;
                                self.set_status("Client approved server access request");
                            }
                            Err(error) => {
                                self.push_log(format!("Failed to send approve decision: {error}"));
                            }
                        }
                    }
                });
            });
    }

    fn draw_host_consent_prompt(&mut self, ctx: &egui::Context) {
        let Some(prompt) = self.pending_host_consent.clone() else {
            return;
        };

        egui::Window::new("Host Consent Required")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Incoming Remote Session")
                        .strong()
                        .size(18.0),
                );
                ui.add_space(6.0);
                ui.label(format!("Requester: {}", prompt.requester_id));
                ui.label(format!("Remote Address: {}", prompt.remote_addr));
                ui.label(format!("Target Session: {}", prompt.target_session));
                ui.add_space(10.0);
                ui.label("Approve to activate desktop stream and optional input control.");
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new("Deny").fill(Color32::from_rgb(128, 46, 57)))
                        .clicked()
                    {
                        match self.ui_bridge.respond_host_consent(false) {
                            Ok(()) => {
                                self.pending_host_consent = None;
                                self.set_status("Host denied local consent");
                            }
                            Err(error) => {
                                self.push_log(format!("Failed to send host deny decision: {error}"));
                            }
                        }
                    }

                    if ui
                        .add(egui::Button::new("Approve").fill(Color32::from_rgb(44, 125, 83)))
                        .clicked()
                    {
                        match self.ui_bridge.respond_host_consent(true) {
                            Ok(()) => {
                                self.pending_host_consent = None;
                                self.set_status("Host approved local consent");
                            }
                            Err(error) => {
                                self.push_log(format!("Failed to send host approve decision: {error}"));
                            }
                        }
                    }
                });
            });
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped_paths: Vec<PathBuf> = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .filter_map(|file| file.path.clone())
                .collect()
        });

        for path in dropped_paths {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default();

            let parsed_seed = if matches!(
                extension.as_str(),
                "png" | "jpg" | "jpeg" | "bmp" | "webp"
            ) {
                decode_qr_from_image_path(&path)
            } else {
                load_connection_seed_from_file_path(&path)
            };

            match parsed_seed {
                Ok(seed) => {
                    self.access_id_input = seed;
                    self.active_tab = ActiveTab::ClientMode;
                    self.set_status("Connection seed imported from dropped file");
                    self.push_log(format!("Loaded dropped file {}", path.display()));
                }
                Err(error) => {
                    self.push_log(format!(
                        "Failed to import dropped file {}: {error}",
                        path.display()
                    ));
                }
            }
        }
    }
    fn sync_advertise_addr_port(&mut self) {
        let input = self.host_advertise_addr_input.trim();
        if input.is_empty() {
            return;
        }
        if let Ok(socket_addr) = input.parse::<SocketAddr>() {
            if socket_addr.port() != self.host_port {
                self.host_advertise_addr_input = format!("{}:{}", socket_addr.ip(), self.host_port);
            }
        } else if let Ok(ip) = input.parse::<IpAddr>() {
            self.host_advertise_addr_input = format!("{}:{}", ip, self.host_port);
        }
    }

    fn trigger_launch_auto_connect(&mut self) {
        if !self.pending_auto_connect || self.client_running {
            return;
        }

        self.pending_auto_connect = false;
        self.active_tab = ActiveTab::ClientMode;
        self.connect_clicked();
    }
}

impl eframe::App for NexusGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.detecting_public_ip.load(Ordering::Relaxed) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        let detected_addr = {
            if let Ok(mut guard) = self.detected_public_addr.lock() {
                guard.take()
            } else {
                None
            }
        };

        if let Some(addr) = detected_addr {
            self.host_advertise_addr_input = addr.to_string();
            self.client_public_addr_display = addr.to_string();
            self.set_status("Public UDP address resolved via STUN");
            self.push_log(format!("STUN PUBLIC ADDRESS {}", addr));
        }

        if let Ok(addr) = self.client_punch_addr_input.trim().parse::<SocketAddr>() {
            if let Ok(mut guard) = self.ui_bridge.client_punch_addr.lock() {
                *guard = Some(addr);
            }
        } else {
            if let Ok(mut guard) = self.ui_bridge.client_punch_addr.lock() {
                *guard = None;
            }
        }

        self.sync_advertise_addr_port();

        let ip_detection_finished = !self.detecting_public_ip.load(Ordering::Relaxed);
        if ip_detection_finished && !self.has_auto_hosted && !self.host_running && self.active_tab == ActiveTab::HostMode {
            self.has_auto_hosted = true;
            self.start_hosting_clicked();
        }

        self.poll_runtime_events(ctx);
        self.trigger_launch_auto_connect();
        self.handle_dropped_files(ctx);

        paint_app_background(ctx);

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgba_unmultiplied(13, 20, 31, 236))
                    .inner_margin(egui::Margin::symmetric(18.0, 14.0)),
            )
            .show(ctx, |ui| {
                self.draw_header(ui);
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().inner_margin(egui::Margin::symmetric(14.0, 14.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.draw_dashboard(ui);
                });
            });

        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgba_unmultiplied(11, 16, 24, 228))
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0)),
            )
            .show(ctx, |ui| {
                self.draw_status_bar(ui);
            });

        self.draw_copy_notice(ctx);
        self.draw_client_permission_prompt(ctx);
        self.draw_host_consent_prompt(ctx);

        ctx.request_repaint_after(Duration::from_millis(UI_REPAINT_MS));
    }
}

fn apply_modern_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = Color32::from_rgb(9, 13, 20);
    visuals.panel_fill = Color32::from_rgb(9, 13, 20);
    visuals.faint_bg_color = Color32::from_rgb(16, 24, 38);
    visuals.extreme_bg_color = Color32::from_rgb(7, 10, 16);
    visuals.code_bg_color = Color32::from_rgb(11, 18, 30);
    visuals.hyperlink_color = Color32::from_rgb(95, 194, 242);
    visuals.selection.bg_fill = Color32::from_rgb(57, 118, 168);
    visuals.widgets.active.bg_fill = Color32::from_rgb(52, 115, 161);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 81, 113);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(24, 37, 56);
    visuals.window_rounding = Rounding::same(14.0);
    visuals.override_text_color = Some(Color32::from_rgb(225, 236, 248));

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(10.0, 11.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(28.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.5, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(13.0, egui::FontFamily::Monospace),
    );
    ctx.set_style(style);
}

fn paint_app_background(ctx: &egui::Context) {
    let rect = ctx.screen_rect();
    let painter = ctx.layer_painter(egui::LayerId::background());

    painter.rect_filled(rect, 0.0, Color32::from_rgb(6, 10, 16));

    painter.circle_filled(
        rect.left_top() + egui::vec2(170.0, 120.0),
        260.0,
        Color32::from_rgba_unmultiplied(48, 117, 173, 32),
    );
    painter.circle_filled(
        rect.right_top() + egui::vec2(-140.0, 160.0),
        220.0,
        Color32::from_rgba_unmultiplied(33, 156, 121, 28),
    );
    painter.circle_filled(
        rect.left_bottom() + egui::vec2(260.0, -120.0),
        210.0,
        Color32::from_rgba_unmultiplied(159, 124, 74, 20),
    );
}

fn status_chip(ui: &mut egui::Ui, label: &str, fill: Color32) {
    let frame = egui::Frame::none()
        .fill(fill)
        .rounding(Rounding::same(999.0))
        .inner_margin(egui::Margin::symmetric(10.0, 6.0));

    frame.show(ui, |ui| {
        ui.label(
            RichText::new(label)
                .size(11.5)
                .strong()
                .color(Color32::from_rgb(234, 244, 255)),
        );
    });
}

fn card(ui: &mut egui::Ui, title: &str, subtitle: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(Color32::from_rgba_unmultiplied(19, 29, 45, 220))
        .stroke(Stroke::new(1.0, Color32::from_rgb(52, 75, 106)))
        .rounding(Rounding::same(14.0))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(title)
                    .size(18.0)
                    .strong()
                    .color(Color32::from_rgb(231, 241, 255)),
            );
            ui.label(
                RichText::new(subtitle)
                    .size(12.5)
                    .color(Color32::from_rgb(157, 177, 201)),
            );
            ui.add_space(8.0);
            add_contents(ui);
        });
}

async fn runtime_dispatch_loop(
    mut runtime_cmd_rx: mpsc::Receiver<RuntimeCommand>,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
) {
    let host_running = Arc::new(AtomicBool::new(false));
    let client_running = Arc::new(AtomicBool::new(false));

    // Spawn STUN network topology diagnostic immediately on startup
    let event_tx_clone = runtime_event_tx.clone();
    tokio::spawn(async move {
        let (topology, public_addr) = run_diagnostics(0).await;
        let _ = event_tx_clone.send(RuntimeEvent::DiagnosticsCompleted { topology, public_addr }).await;
    });

    while let Some(command) = runtime_cmd_rx.recv().await {
        match command {
            RuntimeCommand::StartHosting(config) => {
                if host_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    let _ = runtime_event_tx
                        .send(RuntimeEvent::Error(
                            "host runtime is already active".to_string(),
                        ))
                        .await;
                    continue;
                }

                let event_tx = runtime_event_tx.clone();
                let host_running_flag = Arc::clone(&host_running);
                let bridge = Arc::clone(&ui_bridge);

                tokio::spawn(async move {
                    let _ = event_tx.send(RuntimeEvent::HostLifecycle { running: true }).await;
                    let _ = event_tx
                        .send(RuntimeEvent::SessionStatus(
                            "Host runtime started".to_string(),
                        ))
                        .await;

                    let run_result =
                        run_server_session(config, event_tx.clone(), bridge).await;

                    host_running_flag.store(false, Ordering::Release);
                    let _ = event_tx.send(RuntimeEvent::HostLifecycle { running: false }).await;

                    match run_result {
                        Ok(()) => {
                            let _ = event_tx
                                .send(RuntimeEvent::SessionStatus(
                                    "Host runtime ended".to_string(),
                                ))
                                .await;
                        }
                        Err(error) => {
                            let _ = event_tx
                                .send(RuntimeEvent::Error(format!("Host runtime failed: {error}")))
                                .await;
                        }
                    }
                });
            }
            RuntimeCommand::ConnectWithAccessId {
                access_id,
                display_name,
                transport_mode,
            } => {
                if client_running
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    let _ = runtime_event_tx
                        .send(RuntimeEvent::Error(
                            "client runtime is already active".to_string(),
                        ))
                        .await;
                    continue;
                }

                let parsed_access_id = match parse_connection_seed(&access_id) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        client_running.store(false, Ordering::Release);
                        let _ = runtime_event_tx
                            .send(RuntimeEvent::Error(format!(
                                "invalid connection seed supplied by UI: {error}"
                            )))
                            .await;
                        continue;
                    }
                };

                let event_tx = runtime_event_tx.clone();
                let client_running_flag = Arc::clone(&client_running);
                let bridge = Arc::clone(&ui_bridge);

                tokio::spawn(async move {
                    let _ = event_tx
                        .send(RuntimeEvent::ClientLifecycle { running: true })
                        .await;
                    let _ = event_tx
                        .send(RuntimeEvent::SessionStatus(
                            "Client runtime connecting".to_string(),
                        ))
                        .await;

                    let run_result = run_client_session(
                        parsed_access_id,
                        display_name,
                        transport_mode,
                        event_tx.clone(),
                        bridge,
                    )
                    .await;

                    client_running_flag.store(false, Ordering::Release);
                    let _ = event_tx
                        .send(RuntimeEvent::ClientLifecycle { running: false })
                        .await;

                    match run_result {
                        Ok(()) => {
                            let _ = event_tx
                                .send(RuntimeEvent::SessionStatus(
                                    "Client runtime ended".to_string(),
                                ))
                                .await;
                        }
                        Err(error) => {
                            let _ = event_tx
                                .send(RuntimeEvent::Error(format!(
                                    "Client runtime failed: {error}"
                                )))
                                .await;
                        }
                    }
                });
            }
            RuntimeCommand::RunDiagnostics => {
                let event_tx = runtime_event_tx.clone();
                tokio::spawn(async move {
                    let (topology, public_addr) = run_diagnostics(0).await;
                    let _ = event_tx.send(RuntimeEvent::DiagnosticsCompleted { topology, public_addr }).await;
                });
            }
        }
    }
}

use tokio_rustls::server::TlsStream as ServerTlsStream;

#[derive(Serialize, Deserialize, Clone)]
pub enum TcpPacket {
    Control(ControlMessage),
    Frame(FramePacket),
}

pub async fn send_tcp_packet<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    packet: &TcpPacket,
) -> Result<()> {
    let payload = bincode::serialize(packet).context("failed to serialize TcpPacket")?;
    let len = u32::try_from(payload.len()).context("packet too large")?;
    stream.write_all(&len.to_le_bytes()).await.context("failed to write TCP length prefix")?;
    stream.write_all(&payload).await.context("failed to write TCP payload")?;
    Ok(())
}

pub async fn recv_tcp_packet<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<TcpPacket> {
    let mut len_buf = [0_u8; 4];
    stream.read_exact(&mut len_buf).await.context("failed to read TCP length prefix")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        bail!("TCP packet too large: {len} bytes");
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await.context("failed to read TCP payload")?;
    let packet = bincode::deserialize(&payload).context("failed to deserialize TcpPacket")?;
    Ok(packet)
}

#[derive(Clone)]
pub enum PacketSender {
    Quic(Arc<tokio::sync::Mutex<SendStream>>),
    Tcp(mpsc::Sender<TcpPacket>),
}

impl PacketSender {
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        match self {
            PacketSender::Quic(stream) => {
                let mut guard = stream.lock().await;
                send_message(&mut *guard, msg).await
            }
            PacketSender::Tcp(tx) => {
                tx.send(TcpPacket::Control(msg.clone())).await
                    .map_err(|_| anyhow!("TCP stream closed"))
            }
        }
    }
}

#[derive(Clone)]
pub enum FrameSender {
    Quic(Arc<tokio::sync::Mutex<SendStream>>),
    Tcp(mpsc::Sender<TcpPacket>),
}

impl FrameSender {
    pub async fn send_frame(&self, frame: &FramePacket) -> Result<()> {
        match self {
            FrameSender::Quic(stream) => {
                let mut guard = stream.lock().await;
                send_message(&mut *guard, frame).await
            }
            FrameSender::Tcp(tx) => {
                tx.send(TcpPacket::Frame(frame.clone())).await
                    .map_err(|_| anyhow!("TCP stream closed"))
            }
        }
    }
}

#[derive(Clone)]
pub enum PacketReceiver {
    Quic(Arc<tokio::sync::Mutex<RecvStream>>),
    Tcp(Arc<tokio::sync::Mutex<mpsc::Receiver<ControlMessage>>>),
}

impl PacketReceiver {
    pub async fn recv_control(&self) -> Result<ControlMessage> {
        match self {
            PacketReceiver::Quic(stream) => {
                let mut guard = stream.lock().await;
                recv_message::<ControlMessage>(&mut *guard).await
            }
            PacketReceiver::Tcp(rx) => {
                let mut guard = rx.lock().await;
                guard.recv().await.context("TCP stream closed")
            }
        }
    }
}

#[derive(Clone)]
pub enum FrameReceiver {
    Quic(Arc<tokio::sync::Mutex<RecvStream>>),
    Tcp(Arc<tokio::sync::Mutex<mpsc::Receiver<FramePacket>>>),
}

impl FrameReceiver {
    pub async fn recv_frame(&self) -> Result<FramePacket> {
        match self {
            FrameReceiver::Quic(stream) => {
                let mut guard = stream.lock().await;
                recv_message::<FramePacket>(&mut *guard).await
            }
            FrameReceiver::Tcp(rx) => {
                let mut guard = rx.lock().await;
                guard.recv().await.context("TCP stream closed")
            }
        }
    }
}

enum ConnectionOrStream {
    Quic(quinn::Connection),
    Tcp(ServerTlsStream<tokio::net::TcpStream>),
}

enum ClientConnectionOrStream {
    Quic(quinn::Connection),
    Tcp(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

async fn run_server_session(
    config: HostRuntimeConfig,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
) -> Result<()> {
    let fps = config.fps.clamp(MIN_FPS, MAX_FPS);
    if fps != config.fps {
        warn!(requested_fps = config.fps, fps, "fps value clamped to supported range");
    }

    let frame_interval_ms = (1000_u64 / fps as u64).max(1);
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let socket = std::net::UdpSocket::bind(bind_addr).context("failed to bind server UDP socket")?;
    let actual_local_addr = socket.local_addr().context("failed to query local address of server socket")?;

    // Perform STUN query using the server's actual socket before passing it to Quinn
    let advertised_addr = if let Some(explicit) = config.advertise_addr {
        explicit
    } else if let Some(public_addr) = detect_public_address_with_socket(&socket).await {
        public_addr
    } else {
        advertised_server_addr(actual_local_addr, None)
    };

    let (server, server_socket) = bind_server(socket).await?;
    let credentials = SessionCredentials::generate();

    // Attempt to bind TCP fallback listener
    let tcp_listener = if config.transport_mode != TransportMode::ForceQuicP2p {
        match tokio::net::TcpListener::bind("0.0.0.0:443").await {
            Ok(listener) => {
                info!("Successfully bound TCP listener to 0.0.0.0:443");
                Some(listener)
            }
            Err(err) => {
                warn!("Failed to bind TCP listener to port 443 (privileges or already in use: {err}). Falling back to ephemeral port.");
                match tokio::net::TcpListener::bind("0.0.0.0:0").await {
                    Ok(listener) => Some(listener),
                    Err(e) => {
                        error!("Failed to bind fallback TCP listener: {e}");
                        None
                    }
                }
            }
        }
    } else {
        None
    };

    let actual_tcp_port = tcp_listener.as_ref().and_then(|l| l.local_addr().ok().map(|addr| addr.port()));

    let access_id = build_access_id(
        advertised_addr,
        &server.certificate_fingerprint,
        &credentials.session_id,
        actual_tcp_port,
    )?;

    runtime_event_tx
        .send(RuntimeEvent::HostReady {
            advertised_addr,
            fingerprint: server.certificate_fingerprint.clone(),
            session_id: credentials.session_id.clone(),
            access_id,
            fps,
            inject_input: config.inject_input,
        })
        .await
        .ok();

    let rustls_server_config = if tcp_listener.is_some() {
        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::Certificate(server.certificate_der.clone())],
                rustls::PrivateKey(server.certificate_key.clone()),
            )
            .context("failed to assemble rustls server config for TCP fallback")?;
        Some(Arc::new(server_config))
    } else {
        None
    };

    let session_state = Arc::new(SessionStateMachine::new());
    session_state.transition(SessionState::Authenticating)?;

    let bridge_clone = Arc::clone(&ui_bridge);
    let server_socket_clone = server_socket.try_clone().ok();
    let punch_task = tokio::spawn(async move {
        if let Some(socket) = server_socket_clone {
            loop {
                let target = {
                    if let Ok(guard) = bridge_clone.client_punch_addr.lock() {
                        *guard
                    } else {
                        None
                    }
                };

                if let Some(addr) = target {
                    let _ = socket.send_to(b"nexus-punch", addr);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    });

    let punch_abort_handle = punch_task.abort_handle();
    let run_result = async move {
        let handshake_start = Instant::now();

        // Accept connection from either QUIC or TCP fallback
        let (connection_or_stream, remote_addr, local_addr, protocol_name) = if let Some(ref listener) = tcp_listener {
            tokio::select! {
                quic_conn = server.accept() => {
                    let quic_conn = quic_conn.context("QUIC server accept failed")?;
                    let remote_addr = quic_conn.remote_address();
                    (ConnectionOrStream::Quic(quic_conn), remote_addr, actual_local_addr, "QUIC".to_string())
                }
                tcp_conn = listener.accept() => {
                    let (tcp_stream, remote_addr) = tcp_conn.context("TCP accept failed")?;
                    let local_tcp_addr = tcp_stream.local_addr().unwrap_or(actual_local_addr);
                    info!(remote = %remote_addr, "accepted TCP connection, performing TLS handshake...");
                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(rustls_server_config.clone().unwrap());
                    let tls_stream = tls_acceptor.accept(tcp_stream).await.context("TLS handshake failed")?;
                    (ConnectionOrStream::Tcp(tls_stream), remote_addr, local_tcp_addr, "TCP".to_string())
                }
            }
        } else {
            let quic_conn = server.accept().await?;
            let remote_addr = quic_conn.remote_address();
            (ConnectionOrStream::Quic(quic_conn), remote_addr, actual_local_addr, "QUIC".to_string())
        };

        punch_abort_handle.abort();

        let handshake_latency = handshake_start.elapsed().as_millis();
        let _ = runtime_event_tx.send(RuntimeEvent::ConnectionEstablished {
            protocol: protocol_name,
            local_addr,
            latency_ms: handshake_latency,
        }).await;

        let mut quic_conn_to_close = None;
        if let ConnectionOrStream::Quic(ref c) = connection_or_stream {
            quic_conn_to_close = Some(c.clone());
        }

        let (control_send, control_recv, frame_stream_send, frame_read_abort) = match connection_or_stream {
            ConnectionOrStream::Quic(connection) => {
                let (control_s, control_r) = connection
                    .accept_bi()
                    .await
                    .context("client did not open a control stream")?;
                let frame_s = connection
                    .open_uni()
                    .await
                    .context("failed to open frame stream")?;

                (
                    PacketSender::Quic(Arc::new(tokio::sync::Mutex::new(control_s))),
                    PacketReceiver::Quic(Arc::new(tokio::sync::Mutex::new(control_r))),
                    FrameSender::Quic(Arc::new(tokio::sync::Mutex::new(frame_s))),
                    None,
                )
            }
            ConnectionOrStream::Tcp(tls_stream) => {
                let (tcp_read, tcp_write) = tokio::io::split(tls_stream);
                let (control_tx, control_rx) = mpsc::channel::<ControlMessage>(256);
                let (frame_tx, _frame_rx) = mpsc::channel::<FramePacket>(256);

                let mut tcp_read = tcp_read;
                let read_task = tokio::spawn(async move {
                    loop {
                        match recv_tcp_packet(&mut tcp_read).await {
                            Ok(TcpPacket::Control(msg)) => {
                                if control_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            Ok(TcpPacket::Frame(frame)) => {
                                if frame_tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                info!("TCP read task closed: {err}");
                                break;
                            }
                        }
                    }
                });

                let (tcp_send_tx, mut tcp_send_rx) = mpsc::channel::<TcpPacket>(256);
                let mut tcp_write = tcp_write;
                let write_task = tokio::spawn(async move {
                    while let Some(packet) = tcp_send_rx.recv().await {
                        if let Err(err) = send_tcp_packet(&mut tcp_write, &packet).await {
                            error!("TCP write task failed: {err}");
                            break;
                        }
                    }
                });

                (
                    PacketSender::Tcp(tcp_send_tx.clone()),
                    PacketReceiver::Tcp(Arc::new(tokio::sync::Mutex::new(control_rx))),
                    FrameSender::Tcp(tcp_send_tx),
                    Some((read_task, write_task)),
                )
            }
        };

        let incoming_auth = wait_for_auth_request(&control_recv).await?;

        let peer_addr = remote_addr;

        runtime_event_tx
            .send(RuntimeEvent::IncomingSession {
                remote_addr: peer_addr,
                requester_id: incoming_auth.requester_id.clone(),
                target_session: incoming_auth.target_id.clone(),
            })
            .await
            .ok();

        if let Err(auth_error) = credentials.verify(&incoming_auth.target_id) {
            let _ = session_state.transition(SessionState::Rejected);
            error!(
                ?auth_error,
                remote = %peer_addr,
                requester_id = %incoming_auth.requester_id,
                "SECURITY: authentication failed"
            );

            let _ = control_send.send_control(
                &ControlMessage::AuthResult {
                    success: false,
                    message: "AuthenticationFailed".to_string(),
                },
            )
            .await;

            if let Some(ref c) = quic_conn_to_close {
                c.close(VarInt::from_u32(1), b"authentication failed");
            }
            let _ = session_state.transition(SessionState::Terminated);
            return Ok(());
        }

        control_send.send_control(
            &ControlMessage::AuthResult {
                success: true,
                message: "AuthenticationSucceeded".to_string(),
            },
        )
        .await
        .context("failed to send authentication result")?;

        control_send.send_control(
            &ControlMessage::AccessRequest {
                session_id: incoming_auth.target_id.clone(),
            },
        )
        .await
        .context("failed to send access request to client")?;

        let client_approved = wait_for_client_access_decision(&control_recv).await?;
        if !client_approved {
            let _ = session_state.transition(SessionState::Rejected);
            runtime_event_tx
                .send(RuntimeEvent::SessionStatus(
                    "Client denied access request".to_string(),
                ))
                .await
                .ok();

            let _ = control_send.send_control(
                &ControlMessage::SessionConsent { approved: false },
            )
            .await;

            if let Some(ref c) = quic_conn_to_close {
                c.close(VarInt::from_u32(3), b"client denied access request");
            }
            let _ = session_state.transition(SessionState::Terminated);
            return Ok(());
        }

        session_state.transition(SessionState::PendingConsent)?;

        let approved = request_host_consent(
            peer_addr,
            &incoming_auth,
            &runtime_event_tx,
            &ui_bridge,
        )
        .await?;
        control_send.send_control(&ControlMessage::SessionConsent { approved })
            .await
            .context("failed to send session consent result")?;

        if !approved {
            let _ = session_state.transition(SessionState::Rejected);
            error!(
                requester_id = %incoming_auth.requester_id,
                remote = %peer_addr,
                error = %SecurityError::UserConsentDenied,
                "SECURITY: local user denied consent"
            );
            if let Some(ref c) = quic_conn_to_close {
                c.close(VarInt::from_u32(2), b"user denied consent");
            }
            let _ = session_state.transition(SessionState::Terminated);
            return Ok(());
        }

        session_state.transition(SessionState::Active)?;

        let input = Arc::new(InputController::new()?);
        input.set_state(InputSessionState::Active);

        control_send.send_control(
            &ControlMessage::Ack(format!(
                "session-approved mode={}",
                if config.inject_input { "inject" } else { "preview" }
            )),
        )
        .await
        .context("failed to send session approval acknowledgement")?;

        let session_state_for_control = Arc::clone(&session_state);
        let input_for_control = Arc::clone(&input);
        let inject_input = config.inject_input;
        let control_send_clone = control_send.clone();
        let control_task = tokio::spawn(async move {
            loop {
                match control_recv.recv_control().await {
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

                        if let Err(error) = control_send_clone.send_control(
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

                        if let Err(error) = control_send_clone.send_control(
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

        let mut capturer = ScreenCapturer::new()?;
        let mut ticker = time::interval(Duration::from_millis(frame_interval_ms));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

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

            if let Err(error) = frame_stream_send.send_frame(&packet).await {
                info!(?error, "frame stream ended");
                break;
            }

            info!(sequence = packet.sequence, bytes = packet.pixels.len(), "sent frame");
        }

        input.set_state(InputSessionState::Inactive);
        let _ = session_state.transition(SessionState::Terminated);
        if let Some(ref c) = quic_conn_to_close {
            c.close(VarInt::from_u32(0), b"server shutdown");
        }
        let _ = control_task.await;
        if let Some((read_task, write_task)) = frame_read_abort {
            read_task.abort();
            write_task.abort();
        }
        Ok(())
    }.await;

    punch_task.abort();
    run_result
}

async fn run_client_session(
    parsed_access_id: ParsedAccessId,
    display_name: Option<String>,
    transport_mode: TransportMode,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
) -> Result<()> {
    let use_quic = match transport_mode {
        TransportMode::ForceHttpsTcp => false,
        TransportMode::ForceQuicP2p => true,
        TransportMode::AutoSelect => true,
    };

    let quic_result = if use_quic {
        let (client, client_socket) =
            bind_client(SocketAddr::from(([0, 0, 0, 0], 0)), parsed_access_id.fingerprint.clone())
                .await?;

        let host_addr = parsed_access_id.server_addr;
        let client_socket_clone = client_socket.try_clone().ok();
        let punch_task = tokio::spawn(async move {
            if let Some(socket) = client_socket_clone {
                loop {
                    let _ = socket.send_to(b"nexus-punch", host_addr);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        });

        let conn_fut = client.connect(parsed_access_id.server_addr, "localhost");
        let conn_res = if transport_mode == TransportMode::AutoSelect {
            match tokio::time::timeout(Duration::from_secs(3), conn_fut).await {
                Ok(res) => res,
                Err(_) => {
                    punch_task.abort();
                    Err(anyhow!("QUIC connection attempt timed out after 3s"))
                }
            }
        } else {
            conn_fut.await
        };

        match conn_res {
            Ok(connection) => {
                punch_task.abort();
                Some((connection, punch_task))
            }
            Err(e) => {
                punch_task.abort();
                if transport_mode == TransportMode::AutoSelect {
                    warn!("QUIC connection failed: {e}. Falling back to TCP...");
                    None
                } else {
                    return Err(e).context("QUIC connection failed");
                }
            }
        }
    } else {
        None
    };

    let handshake_start = Instant::now();

    let connection_or_stream = if let Some((connection, _punch_task)) = quic_result {
        ClientConnectionOrStream::Quic(connection)
    } else {
        let target_tcp_port = parsed_access_id.tcp_port.unwrap_or(443);
        let host_ip = parsed_access_id.server_addr.ip();
        let host_tcp_addr = SocketAddr::new(host_ip, target_tcp_port);

        info!("Connecting via TCP fallback to {}...", host_tcp_addr);
        let tcp_stream = tokio::net::TcpStream::connect(host_tcp_addr).await
            .context("failed to connect TCP fallback stream")?;

        info!("TCP stream connected. Performing TLS handshake...");
        let rustls_client_config = build_pinned_rustls_client_config(parsed_access_id.fingerprint.clone())
            .context("failed to build rustls client config for TCP fallback")?;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_client_config));
        let domain = rustls::ServerName::try_from("localhost")?;
        let tls_stream = connector.connect(domain, tcp_stream).await
            .context("TLS handshake failed over TCP fallback")?;

        ClientConnectionOrStream::Tcp(tls_stream)
    };

    let handshake_latency = handshake_start.elapsed().as_millis();
    let protocol = match connection_or_stream {
        ClientConnectionOrStream::Quic(_) => "QUIC".to_string(),
        ClientConnectionOrStream::Tcp(_) => "TCP".to_string(),
    };
    let local_addr = match connection_or_stream {
        ClientConnectionOrStream::Quic(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        ClientConnectionOrStream::Tcp(ref s) => s.get_ref().0.local_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
    };

    let _ = runtime_event_tx.send(RuntimeEvent::ConnectionEstablished {
        protocol,
        local_addr,
        latency_ms: handshake_latency,
    }).await;

    let mut quic_conn_to_close = None;
    if let ClientConnectionOrStream::Quic(ref c) = connection_or_stream {
        quic_conn_to_close = Some(c.clone());
    }

    let run_result = async move {
        let (control_send, control_recv, frame_recv, frame_read_abort) = match connection_or_stream {
            ClientConnectionOrStream::Quic(connection) => {
                let (control_s, control_r) = connection
                    .open_bi()
                    .await
                    .context("failed to open control stream")?;
                let frame_r = connection
                    .accept_uni()
                    .await
                    .context("server did not open a frame stream")?;

                (
                    PacketSender::Quic(Arc::new(tokio::sync::Mutex::new(control_s))),
                    PacketReceiver::Quic(Arc::new(tokio::sync::Mutex::new(control_r))),
                    FrameReceiver::Quic(Arc::new(tokio::sync::Mutex::new(frame_r))),
                    None,
                )
            }
            ClientConnectionOrStream::Tcp(tls_stream) => {
                let (tcp_read, tcp_write) = tokio::io::split(tls_stream);
                let (control_tx, control_rx) = mpsc::channel::<ControlMessage>(256);
                let (frame_tx, frame_rx) = mpsc::channel::<FramePacket>(256);

                let mut tcp_read = tcp_read;
                let read_task = tokio::spawn(async move {
                    loop {
                        match recv_tcp_packet(&mut tcp_read).await {
                            Ok(TcpPacket::Control(msg)) => {
                                if control_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            Ok(TcpPacket::Frame(frame)) => {
                                if frame_tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                info!("TCP read task closed: {err}");
                                break;
                            }
                        }
                    }
                });

                let (tcp_send_tx, mut tcp_send_rx) = mpsc::channel::<TcpPacket>(256);
                let mut tcp_write = tcp_write;
                let write_task = tokio::spawn(async move {
                    while let Some(packet) = tcp_send_rx.recv().await {
                        if let Err(err) = send_tcp_packet(&mut tcp_write, &packet).await {
                            error!("TCP write task failed: {err}");
                            break;
                        }
                    }
                });

                (
                    PacketSender::Tcp(tcp_send_tx.clone()),
                    PacketReceiver::Tcp(Arc::new(tokio::sync::Mutex::new(control_rx))),
                    FrameReceiver::Tcp(Arc::new(tokio::sync::Mutex::new(frame_rx))),
                    Some((read_task, write_task)),
                )
            }
        };

        let session_state = Arc::new(SessionStateMachine::new());
        session_state.transition(SessionState::Authenticating)?;

        control_send.send_control(
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

        control_send.send_control(
            &ControlMessage::AuthRequest {
                requester_id,
                target_id: parsed_access_id.target_id.clone(),
            },
        )
        .await?;

        wait_for_auth_result(&control_recv).await?;

        let requested_session_id = wait_for_access_request(&control_recv).await?;
        let client_approved = request_client_permission(
            parsed_access_id.server_addr,
            &requested_session_id,
            &runtime_event_tx,
            &ui_bridge,
        )
        .await?;

        control_send.send_control(
            &ControlMessage::AccessDecision {
                approved: client_approved,
            },
        )
        .await
        .context("failed to send client access decision")?;

        if !client_approved {
            let _ = session_state.transition(SessionState::Rejected);
            info!("local client denied access request");
            if let Some(ref c) = quic_conn_to_close {
                c.close(VarInt::from_u32(3), b"client denied access request");
            }
            let _ = session_state.transition(SessionState::Terminated);
            return Ok(());
        }

        session_state.transition(SessionState::PendingConsent)?;

        wait_for_session_consent(&control_recv).await?;
        session_state.transition(SessionState::Active)?;

        let (viewer_frame_tx, mut viewer_input_rx) =
            spawn_remote_viewer("NexusP2P - Remote Session [Active]")?;

        let session_state_for_input = Arc::clone(&session_state);
        let control_send_clone = control_send.clone();
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

                if let Err(error) = control_send_clone.send_control(&message).await {
                    warn!(?error, "failed to forward viewer input event");
                    break;
                }
            }
        });

        let control_recv_clone = control_recv.clone();
        let ack_task = tokio::spawn(async move {
            loop {
                match control_recv_clone.recv_control().await {
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

        loop {
            match frame_recv.recv_frame().await {
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

        let _ = session_state.transition(SessionState::Terminated);
        if let Some(ref c) = quic_conn_to_close {
            c.close(VarInt::from_u32(0), b"client shutdown");
        }
        input_task.abort();
        let _ = input_task.await;
        ack_task.abort();
        let _ = ack_task.await;
        if let Some((read_task, write_task)) = frame_read_abort {
            read_task.abort();
            write_task.abort();
        }
        Ok(())
    }.await;

    run_result
}

async fn request_client_permission(
    server_addr: SocketAddr,
    session_id: &str,
    runtime_event_tx: &mpsc::Sender<RuntimeEvent>,
    ui_bridge: &Arc<UiBridge>,
) -> Result<bool> {
    if let Ok(value) = std::env::var("NEXUS_AUTO_CLIENT_PERMISSION") {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "y") {
            warn!("NEXUS_AUTO_CLIENT_PERMISSION enabled: auto-approving client-side request");
            return Ok(true);
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "n") {
            warn!("NEXUS_AUTO_CLIENT_PERMISSION enabled: auto-denying client-side request");
            return Ok(false);
        }
    }

    let (decision_tx, decision_rx) = oneshot::channel();
    ui_bridge.install_client_permission_sender(decision_tx)?;

    runtime_event_tx
        .send(RuntimeEvent::ClientPermissionRequested {
            server_addr,
            session_id: session_id.to_string(),
        })
        .await
        .ok();

    match time::timeout(Duration::from_secs(180), decision_rx).await {
        Ok(Ok(approved)) => Ok(approved),
        Ok(Err(_)) => Err(anyhow!("client permission response channel was closed")),
        Err(_) => {
            ui_bridge.clear_client_permission_sender();
            Err(anyhow!("client permission request timed out"))
        }
    }
}

async fn request_host_consent(
    remote_addr: SocketAddr,
    incoming_auth: &IncomingAuth,
    runtime_event_tx: &mpsc::Sender<RuntimeEvent>,
    ui_bridge: &Arc<UiBridge>,
) -> Result<bool> {
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

    let (decision_tx, decision_rx) = oneshot::channel();
    ui_bridge.install_host_consent_sender(decision_tx)?;

    runtime_event_tx
        .send(RuntimeEvent::HostConsentRequested {
            requester_id: incoming_auth.requester_id.clone(),
            remote_addr,
            target_session: incoming_auth.target_id.clone(),
        })
        .await
        .ok();

    match time::timeout(Duration::from_secs(180), decision_rx).await {
        Ok(Ok(approved)) => Ok(approved),
        Ok(Err(_)) => Err(anyhow!("host consent response channel was closed")),
        Err(_) => {
            ui_bridge.clear_host_consent_sender();
            Err(anyhow!("host consent request timed out"))
        }
    }
}

async fn wait_for_auth_request(control_recv: &PacketReceiver) -> Result<IncomingAuth> {
    let mut saw_hello = false;

    loop {
        match control_recv.recv_control().await {
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
            }) => {
                if !saw_hello {
                    warn!("client sent auth request before hello");
                }
                return Ok(IncomingAuth {
                    requester_id,
                    target_id,
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

async fn wait_for_auth_result(control_recv: &PacketReceiver) -> Result<()> {
    loop {
        match control_recv.recv_control().await {
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

async fn wait_for_access_request(control_recv: &PacketReceiver) -> Result<String> {
    loop {
        match control_recv.recv_control().await {
            Ok(ControlMessage::AccessRequest { session_id }) => {
                if session_id.trim().is_empty() {
                    bail!("server sent empty session ID in access request");
                }
                return Ok(session_id);
            }
            Ok(ControlMessage::Ack(text)) => {
                info!(%text, "received server acknowledgement while waiting for access request");
            }
            Ok(other) => {
                error!(
                    ?other,
                    "SECURITY: blocked unexpected packet while waiting for access request"
                );
            }
            Err(error) => {
                return Err(error).context("failed while waiting for access request");
            }
        }
    }
}

async fn wait_for_client_access_decision(control_recv: &PacketReceiver) -> Result<bool> {
    loop {
        match control_recv.recv_control().await {
            Ok(ControlMessage::AccessDecision { approved }) => {
                return Ok(approved);
            }
            Ok(other) => {
                error!(
                    ?other,
                    "SECURITY: blocked unexpected packet while waiting for client decision"
                );
            }
            Err(error) => {
                return Err(error).context("failed while waiting for client access decision");
            }
        }
    }
}

async fn wait_for_session_consent(control_recv: &PacketReceiver) -> Result<()> {
    loop {
        match control_recv.recv_control().await {
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

fn parse_stun_mapped_address(buf: &[u8]) -> Option<SocketAddr> {
    let response_len = buf.len();
    let mut offset = 20;
    while offset + 4 <= response_len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > response_len {
            break;
        }
        let attr_val = &buf[offset..offset + attr_len];

        if attr_type == 0x0020 { // XOR-MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_val[1];
                if family == 0x01 { // IPv4
                    let x_port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let port = x_port ^ 0x2112;
                    let mut ip_bytes = [0u8; 4];
                    ip_bytes.copy_from_slice(&attr_val[4..8]);
                    let ip_u32 = u32::from_be_bytes(ip_bytes) ^ 0x2112A442;
                    let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));
                    return Some(SocketAddr::new(ip, port));
                }
            }
        } else if attr_type == 0x0001 { // MAPPED-ADDRESS
            if attr_len >= 8 {
                let family = attr_val[1];
                if family == 0x01 { // IPv4
                    let port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                    let ip = IpAddr::V4(Ipv4Addr::new(attr_val[4], attr_val[5], attr_val[6], attr_val[7]));
                    return Some(SocketAddr::new(ip, port));
                }
            }
        }

        offset += (attr_len + 3) & !3;
    }
    None
}

async fn detect_public_address_with_socket(socket: &std::net::UdpSocket) -> Option<SocketAddr> {
    let socket_clone = socket.try_clone().ok()?;
    socket_clone.set_nonblocking(true).ok()?;
    let async_socket = tokio::net::UdpSocket::from_std(socket_clone).ok()?;

    let servers = [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun3.l.google.com:19302",
        "stun4.l.google.com:19302",
        "stun.stunprotocol.org:3478",
        "stun.ekiga.net:3478",
        "stun.ideasip.com:3478",
    ];

    let mut stun_request = [0u8; 20];
    stun_request[0..2].copy_from_slice(&[0x00, 0x01]); // Binding Request
    stun_request[2..4].copy_from_slice(&[0x00, 0x00]);
    stun_request[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
    let mut tx_id = [0u8; 12];
    for i in 0..12 {
        tx_id[i] = rand::random::<u8>();
    }
    stun_request[8..20].copy_from_slice(&tx_id);

    // Resolve STUN servers in parallel
    let mut resolve_tasks = Vec::new();
    for &server_str in &servers {
        resolve_tasks.push(tokio::spawn(async move {
            tokio::net::lookup_host(server_str).await
                .map(|iter| iter.collect::<Vec<_>>())
                .unwrap_or_default()
        }));
    }

    let mut targets = Vec::new();
    for task in resolve_tasks {
        if let Ok(addrs) = task.await {
            for addr in addrs {
                if addr.is_ipv4() {
                    targets.push(addr);
                }
            }
        }
    }

    if targets.is_empty() {
        return None;
    }

    // Send STUN binding requests to all resolved IPv4 addresses
    for &addr in &targets {
        let _ = async_socket.send_to(&stun_request, addr).await;
    }

    // Wait for the first valid response with a 3.0s global timeout
    let start_time = Instant::now();
    let timeout_dur = Duration::from_secs(3);
    let mut buf = [0u8; 512];

    while start_time.elapsed() < timeout_dur {
        let remaining = timeout_dur.saturating_sub(start_time.elapsed());
        if remaining.is_zero() {
            break;
        }

        let recv_result = tokio::time::timeout(
            remaining,
            async_socket.recv_from(&mut buf)
        ).await;

        if let Ok(Ok((len, _))) = recv_result {
            if len >= 20 && buf[0..2] == [0x01, 0x01] && buf[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                if buf[8..20] == tx_id {
                    if let Some(mapped_addr) = parse_stun_mapped_address(&buf[..len]) {
                        return Some(mapped_addr);
                    }
                }
            }
        }
    }

    None
}



fn build_access_id(server_addr: SocketAddr, fingerprint: &str, target_id: &str, tcp_port: Option<u16>) -> Result<String> {
    let payload = AccessIdPayload {
        version: ACCESS_ID_VERSION,
        server_addr: server_addr.to_string(),
        fingerprint: normalize_fingerprint_hex(fingerprint)
            .context("failed to normalize fingerprint for access ID")?,
        target_id: target_id.to_string(),
        tcp_port,
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
        tcp_port: payload.tcp_port,
    })
}

fn copy_text_to_clipboard(value: &str) -> Result<()> {
    let mut clipboard = Clipboard::new().context("failed to open clipboard")?;
    clipboard
        .set_text(value.to_string())
        .context("failed to write text to clipboard")
}

fn paste_text_from_clipboard() -> Result<String> {
    let mut clipboard = Clipboard::new().context("failed to open clipboard")?;
    let text = clipboard
        .get_text()
        .context("clipboard does not contain text")?;
    let trimmed = text.trim().to_string();

    if trimmed.is_empty() {
        bail!("clipboard text is empty")
    }

    Ok(trimmed)
}

fn save_connection_payload_file_from_seed(seed: &str) -> Result<PathBuf> {
    let payload = if let Ok(raw) = decode_connection_seed_base64(seed) {
        raw
    } else {
        let parsed = parse_connection_seed(seed)?;
        build_connection_payload_bytes(parsed.server_addr, &parsed.fingerprint, &parsed.target_id, parsed.tcp_port)?
    };

    let Some(path) = rfd::FileDialog::new()
        .set_file_name("connection.nexus")
        .add_filter("Nexus Binary Payload", &["nexus"])
        .save_file()
    else {
        bail!("export canceled")
    };

    fs::write(&path, payload).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn save_access_id_file(access_id: &str) -> Result<PathBuf> {
    save_connection_payload_file_from_seed(access_id)
}

fn save_access_id_qr_png(access_id: &str) -> Result<std::path::PathBuf> {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name("access-id-qr.png")
        .add_filter("PNG Image", &["png"])
        .save_file()
    else {
        bail!("QR export canceled")
    };

    let matrix = qrcode_generator::to_matrix(access_id, QrCodeEcc::Quartile)
        .context("failed to build QR matrix")?;

    let modules = matrix.len();
    if modules == 0 {
        bail!("QR matrix is empty")
    }

    let scale = 12_u32;
    let border = 4_u32;
    let side = (modules as u32 + border * 2) * scale;
    let mut image = image::ImageBuffer::<image::Luma<u8>, Vec<u8>>::from_pixel(
        side,
        side,
        image::Luma([255_u8]),
    );

    for (row_index, row) in matrix.iter().enumerate() {
        for (column_index, cell) in row.iter().enumerate() {
            if !*cell {
                continue;
            }

            let pixel_x = (column_index as u32 + border) * scale;
            let pixel_y = (row_index as u32 + border) * scale;

            for y in 0..scale {
                for x in 0..scale {
                    image.put_pixel(pixel_x + x, pixel_y + y, image::Luma([0_u8]));
                }
            }
        }
    }

    image
        .save(&path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn load_connection_seed_file() -> Result<String> {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Nexus Connection", &["nexus", "txt"])
        .pick_file()
    else {
        bail!("import canceled")
    };

    load_connection_seed_from_file_path(&path)
}

fn load_connection_seed_from_file_path(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.is_empty() {
        bail!("connection file is empty")
    }

    if bytes.len() == CONNECTION_PAYLOAD_BYTES {
        let parsed = parse_connection_payload_bytes(&bytes)?;
        let payload = build_connection_payload_bytes(
            parsed.server_addr,
            &parsed.fingerprint,
            &parsed.target_id,
            parsed.tcp_port,
        )?;
        return Ok(URL_SAFE_NO_PAD.encode(payload));
    }

    if let Ok(text) = std::str::from_utf8(&bytes) {
        let seed = text.trim();
        if seed.is_empty() {
            bail!("connection file is empty")
        }

        if parse_connection_seed(seed).is_ok() {
            return Ok(seed.to_string());
        }
    }

    bail!(
        "unsupported connection file format (expected {}-byte compact payload or text seed)",
        CONNECTION_PAYLOAD_BYTES
    )
}

fn load_access_id_file() -> Result<String> {
    load_connection_seed_file()
}

fn load_access_id_from_qr_file() -> Result<String> {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Image", &["png", "jpg", "jpeg", "bmp", "webp"])
        .pick_file()
    else {
        bail!("QR import canceled")
    };

    decode_qr_from_image_path(&path)
}

fn load_access_id_from_clipboard_image() -> Result<String> {
    let mut clipboard = Clipboard::new().context("failed to open clipboard")?;

    let image = clipboard
        .get_image()
        .context("clipboard does not contain an image")?;

    let width = u32::try_from(image.width).context("clipboard image width too large")?;
    let height = u32::try_from(image.height).context("clipboard image height too large")?;
    let rgba_bytes = image.bytes.into_owned();

    let rgba = image::RgbaImage::from_raw(width, height, rgba_bytes)
        .context("clipboard image format is not RGBA")?;

    decode_qr_from_dynamic_image(image::DynamicImage::ImageRgba8(rgba))
}

fn decode_qr_from_image_path(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let image =
        image::load_from_memory(&bytes).with_context(|| format!("invalid image {}", path.display()))?;

    decode_qr_from_dynamic_image(image)
}

fn decode_qr_from_dynamic_image(image: image::DynamicImage) -> Result<String> {
    let gray = image.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();

    for grid in grids {
        if let Ok((_meta, text)) = grid.decode() {
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }

    bail!("no QR payload found in image")
}

fn build_qr_color_image(payload: &str) -> Result<ColorImage> {
    let matrix =
        qrcode_generator::to_matrix(payload, QrCodeEcc::Quartile).context("failed to build QR matrix")?;

    let modules = matrix.len();
    if modules == 0 {
        bail!("QR matrix is empty")
    }

    let scale = 6_usize;
    let border = 3_usize;
    let side = (modules + border * 2) * scale;
    let mut pixels = vec![Color32::WHITE; side * side];

    for (row_index, row) in matrix.iter().enumerate() {
        for (column_index, cell) in row.iter().enumerate() {
            let color = if *cell { Color32::BLACK } else { Color32::WHITE };
            let pixel_x = (column_index + border) * scale;
            let pixel_y = (row_index + border) * scale;

            for y in 0..scale {
                for x in 0..scale {
                    let index = (pixel_y + y) * side + (pixel_x + x);
                    pixels[index] = color;
                }
            }
        }
    }

    Ok(ColorImage {
        size: [side, side],
        pixels,
    })
}

fn parse_connection_seed(seed: &str) -> Result<ParsedAccessId> {
    let trimmed = seed.trim().trim_matches('"');
    if trimmed.is_empty() {
        bail!("connection seed is empty")
    }

    if let Some(inner_seed) = extract_seed_from_deep_link(trimmed) {
        return parse_connection_seed(&inner_seed);
    }

    if let Ok(parsed) = parse_access_id(trimmed) {
        return Ok(parsed);
    }

    if let Ok(payload) = decode_connection_seed_base64(trimmed) {
        return parse_connection_payload_bytes(&payload);
    }

    if let Ok(payload) = decode_connection_seed_mnemonic(trimmed) {
        return parse_connection_payload_bytes(&payload);
    }

    bail!("unsupported connection seed format")
}

fn build_connection_payload_bytes(
    server_addr: SocketAddr,
    fingerprint: &str,
    target_id: &str,
    tcp_port: Option<u16>,
) -> Result<Vec<u8>> {
    debug_assert_eq!(
        CONNECTION_PAYLOAD_USED_BYTES + CONNECTION_PAYLOAD_RESERVED_BYTES,
        CONNECTION_PAYLOAD_BYTES
    );

    let ipv4 = match server_addr.ip() {
        IpAddr::V4(value) => value.octets(),
        IpAddr::V6(_) => bail!("compact connection seed currently supports IPv4 addresses only"),
    };

    let fingerprint_hex = normalize_fingerprint_hex(fingerprint)
        .context("failed to normalize fingerprint for compact seed")?;
    let fingerprint_bytes =
        hex::decode(&fingerprint_hex).context("failed to decode fingerprint bytes")?;
    if fingerprint_bytes.len() < CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES {
        bail!(
            "fingerprint must contain at least {} bytes",
            CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES
        );
    }

    let target_id_bytes = hex::decode(target_id.trim())
        .context("target session ID must be hexadecimal for compact seed")?;
    if target_id_bytes.len() != CONNECTION_PAYLOAD_TARGET_ID_BYTES {
        bail!(
            "target session ID must contain exactly {} bytes",
            CONNECTION_PAYLOAD_TARGET_ID_BYTES
        );
    }

    let version_index = 0;
    let family_index = 1;
    let ip_start = CONNECTION_PAYLOAD_HEADER_BYTES;
    let ip_end = ip_start + CONNECTION_PAYLOAD_IPV4_BYTES;
    let port_end = ip_end + CONNECTION_PAYLOAD_PORT_BYTES;
    let fingerprint_end = port_end + CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES;
    let target_end = fingerprint_end + CONNECTION_PAYLOAD_TARGET_ID_BYTES;

    let mut payload = [0_u8; CONNECTION_PAYLOAD_BYTES];
    payload[version_index] = CONNECTION_PAYLOAD_VERSION;
    payload[family_index] = CONNECTION_PAYLOAD_FAMILY_IPV4;
    payload[ip_start..ip_end].copy_from_slice(&ipv4);
    payload[ip_end..port_end].copy_from_slice(&server_addr.port().to_be_bytes());
    payload[port_end..fingerprint_end]
        .copy_from_slice(&fingerprint_bytes[..CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES]);
    payload[fingerprint_end..target_end].copy_from_slice(&target_id_bytes);

    // Store TCP port at the remaining 2 reserved bytes
    let tcp_port_val = tcp_port.unwrap_or(0);
    payload[target_end..target_end + 2].copy_from_slice(&tcp_port_val.to_be_bytes());

    Ok(payload.to_vec())
}

fn parse_connection_payload_bytes(payload: &[u8]) -> Result<ParsedAccessId> {
    debug_assert_eq!(
        CONNECTION_PAYLOAD_USED_BYTES + CONNECTION_PAYLOAD_RESERVED_BYTES,
        CONNECTION_PAYLOAD_BYTES
    );

    if payload.len() != CONNECTION_PAYLOAD_BYTES {
        bail!(
            "compact seed must be {} bytes, got {}",
            CONNECTION_PAYLOAD_BYTES,
            payload.len()
        );
    }

    let version_index = 0;
    let family_index = 1;
    let ip_start = CONNECTION_PAYLOAD_HEADER_BYTES;
    let ip_end = ip_start + CONNECTION_PAYLOAD_IPV4_BYTES;
    let port_end = ip_end + CONNECTION_PAYLOAD_PORT_BYTES;
    let fingerprint_end = port_end + CONNECTION_PAYLOAD_FINGERPRINT_PREFIX_BYTES;
    let target_end = fingerprint_end + CONNECTION_PAYLOAD_TARGET_ID_BYTES;

    if payload[version_index] != CONNECTION_PAYLOAD_VERSION {
        bail!(
            "unsupported compact seed version: {} (expected {})",
            payload[version_index],
            CONNECTION_PAYLOAD_VERSION
        );
    }

    if payload[family_index] != CONNECTION_PAYLOAD_FAMILY_IPV4 {
        bail!(
            "unsupported compact seed address family: {}",
            payload[family_index]
        );
    }

    let ip = Ipv4Addr::new(
        payload[ip_start],
        payload[ip_start + 1],
        payload[ip_start + 2],
        payload[ip_start + 3],
    );
    let port = u16::from_be_bytes([payload[ip_end], payload[ip_end + 1]]);

    let fingerprint_prefix = &payload[port_end..fingerprint_end];
    let target_id = &payload[fingerprint_end..target_end];

    let tcp_port_val = u16::from_be_bytes([payload[target_end], payload[target_end + 1]]);
    let tcp_port = if tcp_port_val > 0 { Some(tcp_port_val) } else { None };

    Ok(ParsedAccessId {
        server_addr: SocketAddr::new(IpAddr::V4(ip), port),
        fingerprint: hex::encode(fingerprint_prefix),
        target_id: hex::encode(target_id),
        tcp_port,
    })
}

fn decode_connection_seed_base64(seed: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(seed.trim())
        .context("failed to decode compact seed as base64")?;

    if decoded.len() != CONNECTION_PAYLOAD_BYTES {
        bail!(
            "base64 compact seed must decode to {} bytes",
            CONNECTION_PAYLOAD_BYTES
        );
    }

    Ok(decoded)
}

fn encode_connection_seed_mnemonic(payload: &[u8]) -> Result<String> {
    if payload.len() != CONNECTION_PAYLOAD_BYTES {
        bail!(
            "compact seed must be {} bytes before mnemonic conversion",
            CONNECTION_PAYLOAD_BYTES
        );
    }

    let mnemonic = Mnemonic::from_entropy_in(Language::English, payload)
        .context("failed to encode compact seed as mnemonic")?;
    Ok(mnemonic.to_string())
}

fn decode_connection_seed_mnemonic(seed: &str) -> Result<Vec<u8>> {
    let mnemonic = Mnemonic::parse_in(Language::English, seed.trim())
        .context("failed to parse mnemonic connection seed")?;
    let entropy = mnemonic.to_entropy();

    if entropy.len() != CONNECTION_PAYLOAD_BYTES {
        bail!(
            "mnemonic connection seed must decode to {} bytes",
            CONNECTION_PAYLOAD_BYTES
        );
    }

    Ok(entropy)
}

fn build_connection_deep_link(seed: &str) -> String {
    format!("{DEEP_LINK_PREFIX}/{seed}")
}

fn extract_seed_from_deep_link(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    let lower = trimmed.to_ascii_lowercase();

    let path_prefix = format!("{DEEP_LINK_PREFIX}/").to_ascii_lowercase();
    if lower.starts_with(&path_prefix) {
        let candidate = trimmed[path_prefix.len()..].trim();
        if !candidate.is_empty() {
            return Some(candidate.to_string());
        }
    }

    if !lower.starts_with(DEEP_LINK_PREFIX) {
        return None;
    }

    let query = trimmed.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key.eq_ignore_ascii_case("seed")
            || key.eq_ignore_ascii_case("access-id")
            || key.eq_ignore_ascii_case("access_id")
        {
            let candidate = value.trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }

    None
}

fn parse_launch_connection_seed() -> Option<String> {
    fn parse_seed_from_deep_link(argument: &str) -> Option<String> {
        let normalized = argument.trim().trim_matches('"');
        if !normalized.to_ascii_lowercase().starts_with(DEEP_LINK_PREFIX) {
            return None;
        }

        if let Some(path_seed) = normalized
            .strip_prefix(&(DEEP_LINK_PREFIX.to_string() + "/"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(path_seed.to_string());
        }

        let query = normalized.split_once('?')?.1;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=')?;
            if key.eq_ignore_ascii_case("seed")
                || key.eq_ignore_ascii_case("access-id")
                || key.eq_ignore_ascii_case("access_id")
            {
                let candidate = value.trim();
                if !candidate.is_empty() {
                    return Some(candidate.to_string());
                }
            }
        }

        None
    }

    let mut args = std::env::args().skip(1).peekable();
    while let Some(argument) = args.next() {
        let trimmed = argument.trim().trim_matches('"').to_string();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("--access-id=") {
            let normalized = value.trim().trim_matches('"').to_string();
            if !normalized.is_empty() {
                return Some(normalized);
            }
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("--connect-seed=") {
            let normalized = value.trim().trim_matches('"').to_string();
            if !normalized.is_empty() {
                return Some(normalized);
            }
            continue;
        }

        if trimmed == "--access-id" || trimmed == "--connect-seed" {
            if let Some(next_value) = args.next() {
                let normalized = next_value.trim().trim_matches('"').to_string();
                if !normalized.is_empty() {
                    return Some(normalized);
                }
            }
            continue;
        }

        if let Some(from_link) = parse_seed_from_deep_link(&trimmed) {
            return Some(from_link);
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn register_nexus_protocol_handler() -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let exe_text = current_exe.display().to_string();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (protocol_key, _) = hkcu
        .create_subkey("Software\\Classes\\nexus")
        .context("failed to create protocol root key")?;
    protocol_key
        .set_value("", &"URL:NexusP2P Protocol")
        .context("failed to write protocol display name")?;
    protocol_key
        .set_value("URL Protocol", &"")
        .context("failed to write URL protocol marker")?;

    let (icon_key, _) = protocol_key
        .create_subkey("DefaultIcon")
        .context("failed to create protocol icon key")?;
    icon_key
        .set_value("", &format!("\"{}\",0", exe_text))
        .context("failed to write protocol icon value")?;

    let (command_key, _) = protocol_key
        .create_subkey("shell\\open\\command")
        .context("failed to create protocol command key")?;
    command_key
        .set_value("", &format!("\"{}\" \"%1\"", exe_text))
        .context("failed to write protocol command value")?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn register_nexus_protocol_handler() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_access_id, build_connection_payload_bytes, encode_connection_seed_mnemonic,
        parse_access_id, parse_connection_seed,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn access_id_roundtrip() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5000);
        let fingerprint =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let target_id = "a1b2c3d4e5f6";

        let token = build_access_id(server_addr, fingerprint, target_id, None).expect("build access ID");
        let parsed = parse_access_id(&token).expect("parse access ID");

        assert_eq!(parsed.server_addr, server_addr);
        assert_eq!(parsed.fingerprint, fingerprint);
        assert_eq!(parsed.target_id, target_id);
        assert_eq!(parsed.tcp_port, None);
    }

    #[test]
    fn parse_access_id_rejects_invalid_data() {
        assert!(parse_access_id("invalid-token").is_err());
    }

    #[test]
    fn probe_bip39() {
        let word_list = bip39::Language::English.word_list();
        let first = word_list.iter().next();
        assert_eq!(first, Some(&"abandon"));
    }

    #[test]
    fn connection_seed_roundtrip_supports_base64_and_deep_link() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 24, 8, 19)), 5000);
        let fingerprint =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let target_id = "a1b2c3d4e5f6";

        let payload = build_connection_payload_bytes(server_addr, fingerprint, target_id, None)
            .expect("build compact connection payload");
        let seed = URL_SAFE_NO_PAD.encode(&payload);

        let parsed = parse_connection_seed(&seed).expect("parse base64 connection seed");
        assert_eq!(parsed.server_addr, server_addr);
        assert_eq!(parsed.fingerprint, &fingerprint[..32]);
        assert_eq!(parsed.target_id, target_id);
        assert_eq!(parsed.tcp_port, None);

        let deep_link = format!("nexus://connect/{seed}");
        let parsed_from_link =
            parse_connection_seed(&deep_link).expect("parse deep-link connection seed");
        assert_eq!(parsed_from_link.server_addr, server_addr);
        assert_eq!(parsed_from_link.fingerprint, &fingerprint[..32]);
        assert_eq!(parsed_from_link.target_id, target_id);
        assert_eq!(parsed_from_link.tcp_port, None);
    }

    #[test]
    fn connection_seed_roundtrip_supports_mnemonic() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25)), 5500);
        let fingerprint =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let target_id = "001122334455";

        let payload = build_connection_payload_bytes(server_addr, fingerprint, target_id, None)
            .expect("build compact connection payload");
        let mnemonic =
            encode_connection_seed_mnemonic(&payload).expect("encode mnemonic connection seed");

        let parsed = parse_connection_seed(&mnemonic).expect("parse mnemonic connection seed");
        assert_eq!(parsed.server_addr, server_addr);
        assert_eq!(parsed.fingerprint, &fingerprint[..32]);
        assert_eq!(parsed.target_id, target_id);
        assert_eq!(parsed.tcp_port, None);
    }

    #[test]
    fn connection_seed_roundtrip_with_tcp_port() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 44)), 6000);
        let fingerprint =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let target_id = "aabbccddeeff";
        let tcp_port = Some(443);

        let payload = build_connection_payload_bytes(server_addr, fingerprint, target_id, tcp_port)
            .expect("build compact connection payload with tcp port");
        let mnemonic =
            encode_connection_seed_mnemonic(&payload).expect("encode mnemonic connection seed");

        let parsed = parse_connection_seed(&mnemonic).expect("parse mnemonic connection seed");
        assert_eq!(parsed.server_addr, server_addr);
        assert_eq!(parsed.fingerprint, &fingerprint[..32]);
        assert_eq!(parsed.target_id, target_id);
        assert_eq!(parsed.tcp_port, tcp_port);
    }

    #[tokio::test]
    async fn test_detect_public_ip_with_timeout() {
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            nexus_network::run_diagnostics(0)
        ).await;

        assert!(start.elapsed() < std::time::Duration::from_secs(7), "Public IP detection took too long / hung!");
        match result {
            Ok((topology, maybe_addr)) => {
                println!("Diagnostics completed: topology={:?}, addr={:?}", topology, maybe_addr);
            }
            Err(_) => panic!("Public IP detection hung and triggered outer timeout!"),
        }
    }
}
