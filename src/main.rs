#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod adaptive;
mod actions;
mod delta;
mod frame_codec;
mod history;
mod screenshot;
mod numeric_entry;
mod ui_widgets;
mod short_code;
mod trusted;

use anyhow::{anyhow, bail, Context, Result};
use arboard::Clipboard;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use eframe::egui;
use egui::{Color32, ColorImage, RichText, Rounding, Stroke, TextureHandle, TextureOptions};
use numeric_entry::EditAction;
use ui_widgets::Glyph;
use nexus_core::{
    ControlMessage, FramePacket, SecurityError, SessionCredentials, SessionState,
    SessionStateMachine,
};
use nexus_display::{spawn_remote_viewer, ScreenCapturer, ViewerInputEvent};
use nexus_input::{
    InputController, KeyboardPreview, MousePreview, SessionState as InputSessionState,
};
use nexus_network::{
    accept_connection, connect_to_peer, create_client_endpoint_with_secret, EndpointAddr, RecvStream,
    SendStream, SecretKey,
};
use qrcode_generator::QrCodeEcc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use bip39::{Language, Mnemonic};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkTopology {
    #[default]
    Undetermined,
    OpenInternet,
    ConeNatFriendly,
    SymmetricNatRestrictive,
    UdpBlockedStrict,
}
#[cfg(target_os = "windows")]
use winreg::enums::HKEY_CURRENT_USER;
#[cfg(target_os = "windows")]
use winreg::RegKey;

const PROTOCOL_VERSION: u16 = 5;
const TRUSTED_SESSION_MARKER: &str = "xlink-authenticated-trusted-device-v1";
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_FRAME_WIDTH: u32 = 16_384;
const MAX_FRAME_HEIGHT: u32 = 16_384;
const DEFAULT_PORT: u16 = 0;
const DEFAULT_FPS: u16 = 30;
const MIN_FPS: u16 = 1;
const MAX_FPS: u16 = 60;
const CONNECTION_PAYLOAD_BYTES: usize = 32;
const UI_REPAINT_MS: u64 = 16;
const DEEP_LINK_PREFIX: &str = "nexus://connect";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(25);

/// Child tasks must not outlive a revoked remote-control session.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}


fn main() -> Result<()> {
    init_tracing();
    let trust_registry = trusted::TrustRegistry::load_or_create()
        .context("cannot load Windows-protected device identity")?;

    if let Err(error) = register_nexus_protocol_handler() {
        warn!(?error, "failed to register nexus protocol handler");
    }

    let launch_connection_seed = parse_launch_connection_seed();

    let runtime = Arc::new(Builder::new_multi_thread()
        .enable_all()
        .thread_name("nexus-runtime")
        .build()
        .context("failed to create Tokio runtime")?);

    let (runtime_cmd_tx, runtime_cmd_rx) = mpsc::channel::<RuntimeCommand>(32);
    let (runtime_event_tx, runtime_event_rx) = mpsc::channel::<RuntimeEvent>(256);
    let ui_bridge = Arc::new(UiBridge::default());

    runtime.spawn(runtime_dispatch_loop(
        runtime_cmd_rx,
        runtime_event_tx,
        Arc::clone(&ui_bridge),
        trust_registry.clone(),
    ));

    let mut runtime_event_rx_slot = Some(runtime_event_rx);
    let mut runtime_cmd_tx_slot = Some(runtime_cmd_tx);
    let mut ui_bridge_slot = Some(ui_bridge);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([688.0, 732.0])
            .with_min_inner_size([490.0, 550.0]),
        ..Default::default()
    };

    eframe::run_native(
        "XLINK | Secure Remote Support",
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
                Arc::clone(&runtime),
                trust_registry.clone(),
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
    protocol_version: u8,
    endpoint_id: [u8; 32],
}

#[derive(Debug, Clone)]
struct ParsedAccessId {
    endpoint_id: [u8; 32],
}

#[derive(Debug, Clone)]
struct IncomingAuth {
    requester_id: String,
    target_id: String,
    remember_device: bool,
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
    fps: u16,
    max_width: u16,
    inject_input: bool,
    seed: [u8; 32],
}

#[derive(Debug)]
enum RuntimeCommand {
    StartHosting(HostRuntimeConfig),
    ConnectWithAccessId {
        access_id: String,
        display_name: Option<String>,
        remember_host: bool,
        _transport_mode: TransportMode,
    },
    ConnectTrusted {
        endpoint_id: [u8; 32],
        display_name: Option<String>,
    },
    RunDiagnostics,
    StopHosting,
    DisconnectClient,
}

#[derive(Debug)]
enum RuntimeEvent {
    HostReady {
        advertised_addr: String,
        fingerprint: String,
        session_id: String,
        access_id: String,
        fps: u16,
        inject_input: bool,
    },
    IncomingSession {
        remote_addr: String,
        requester_id: String,
        target_session: String,
    },
    ClientPermissionRequested {
        server_addr: String,
        session_id: String,
    },
    HostConsentRequested {
        requester_id: String,
        remote_addr: String,
        target_session: String,
        remember_requested: bool,
    },
    PairingCodeRevoked,
    HostLifecycle {
        running: bool,
    },
    HostSessionActive {
        active: bool,
    },
    ConnectionAuthenticated { peer: String, direction: history::Direction },
    ClientLifecycle {
        running: bool,
    },
    SessionStatus(String),
    DiagnosticsCompleted {
        topology: NetworkTopology,
        public_addr: Option<String>,
    },
    ConnectionEstablished {
        protocol: String,
        local_addr: String,
        latency_ms: u128,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy)]
struct HostConsentDecision {
    approved: bool,
    remember_technician: bool,
}

#[derive(Default)]
struct UiBridge {
    pending_client_permission_sender: Mutex<Option<oneshot::Sender<bool>>>,
    pending_host_consent_sender: Mutex<Option<oneshot::Sender<HostConsentDecision>>>,
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

    fn install_host_consent_sender(&self, sender: oneshot::Sender<HostConsentDecision>) -> Result<()> {
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

    fn respond_host_consent(&self, decision: HostConsentDecision) -> Result<()> {
        let mut guard = self
            .pending_host_consent_sender
            .lock()
            .map_err(|_| anyhow!("host consent bridge lock poisoned"))?;

        match guard.take() {
            Some(sender) => sender
                .send(decision)
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
    server_addr: String,
    session_id: String,
}

#[derive(Debug, Clone)]
struct HostConsentPrompt {
    requester_id: String,
    remote_addr: String,
    target_session: String,
    remember_requested: bool,
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
    host_max_width: u16,
    host_inject_input: bool,
    show_logs: bool,
    show_preferences: bool,
    show_history: bool,
    recent_history: Option<history::History>,
    code_ready_at: Option<Instant>,
    refocus_number_input: bool,
    numeric_cursor: usize,
    window_was_focused: bool,
    remember_this_computer: bool,
    trust_current_technician: bool,
    trust_registry: trusted::TrustRegistry,
    host_advertise_addr_input: String,

    client_display_name: String,
    pending_client_permission: Option<PermissionPrompt>,
    pending_host_consent: Option<HostConsentPrompt>,

    runtime_cmd_tx: mpsc::Sender<RuntimeCommand>,
    runtime_event_rx: mpsc::Receiver<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,

    host_running: bool,
    host_session_active: bool,
    client_running: bool,
    status_message: String,
    session_logs: VecDeque<String>,
    detected_public_addr: Arc<Mutex<Option<SocketAddr>>>,
    detecting_public_ip: Arc<AtomicBool>,
    _runtime: Arc<Runtime>,
    has_auto_hosted: bool,
    host_seed: [u8; 32],
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
        runtime: Arc<Runtime>,
        trust_registry: trusted::TrustRegistry,
    ) -> Self {
        apply_modern_theme(&cc.egui_ctx);

        let host_port = DEFAULT_PORT;
        let default_advertise = default_advertise_addr(host_port).to_string();
        let pending_auto_connect = launch_connection_seed
            .as_ref()
            .map(|seed| parse_connection_seed(seed).is_ok())
            .unwrap_or(false);

        // Keep an encrypted, per-Windows-user private device identity across
        // restarts so explicitly trusted peers can recognize this machine.
        let host_seed = trust_registry.host_seed()
            .expect("validated DPAPI-backed local identity");

        // Hosting is opt-in. Opening the application must not expose a listener automatically.
        let detected_public_addr = Arc::new(Mutex::new(None));
        let detecting_public_ip = Arc::new(AtomicBool::new(true));

        Self {
            active_tab: if launch_connection_seed.is_some() {
                ActiveTab::ClientMode
            } else {
                ActiveTab::HostMode
            },
            access_id_input: launch_connection_seed.filter(|text| {
                let digits = text.chars().filter(|c| c.is_ascii_digit()).count();
                digits == text.len() && (8..=10).contains(&digits)
            }).unwrap_or_default(),
            generated_access_id: None,
            qr_code_texture: None,
            copied_notice_until: None,
            pending_auto_connect,
            host_port,
            host_fps: DEFAULT_FPS,
            host_max_width: 1280,
            host_inject_input: true,
            show_logs: false,
            show_preferences: false,
            show_history: false,
            recent_history: match history::History::open() {
                Ok(archive) => Some(archive),
                Err(error) => {
                    tracing::warn!(?error, "encrypted connection history unavailable");
                    None
                }
            },
            code_ready_at: None,
            refocus_number_input: true,
            numeric_cursor: 0,
            window_was_focused: false,
            remember_this_computer: false,
            trust_current_technician: false,
            trust_registry,
            host_advertise_addr_input: default_advertise,
            client_display_name: String::new(),
            pending_client_permission: None,
            pending_host_consent: None,
            runtime_cmd_tx,
            runtime_event_rx,
            ui_bridge,
            host_running: false,
            host_session_active: false,
            client_running: false,
            status_message: "Ready".to_string(),
            session_logs: VecDeque::with_capacity(200),
            detected_public_addr,
            detecting_public_ip,
            _runtime: runtime,
            has_auto_hosted: false, // Start the public pairing host on the first UI frame
            host_seed,
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
                    self.code_ready_at = Some(Instant::now());
                    self.host_advertise_addr_input = advertised_addr.to_string();
                    self.client_public_addr_display = advertised_addr.to_string();
                    self.set_status("Ready for a secure support request");
                    self.push_log(format!(
                        "HOST READY endpoint={} session_id={} fps={} mode={}",
                        advertised_addr,
                        session_id,
                        fps,
                        if inject_input { "inject" } else { "preview" }
                    ));
                    self.push_log(format!("HOST CERT SHA256 {}", fingerprint));
                    // Numeric pairing never renders a QR or private key.
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
                    remember_requested,
                } => {
                    self.trust_current_technician = false;
                    self.pending_host_consent = Some(HostConsentPrompt {
                        requester_id,
                        remote_addr,
                        target_session,
                        remember_requested,
                    });
                    self.active_tab = ActiveTab::HostMode;
                    self.set_status("ACTION REQUIRED: approve or deny the technician on this computer");
                }
                RuntimeEvent::HostLifecycle { running } => {
                    self.host_running = running;
                    if !running {
                        self.host_session_active = false;
                    }
                    if !running {
                        self.pending_host_consent = None;
                        self.ui_bridge.clear_host_consent_sender();
                        // The temporary pairing code is revoked, while the
                        // stable device identity remains protected by DPAPI.
                        self.generated_access_id = None;
                        self.code_ready_at = None;
                        self.push_log("Host stopped; old access code invalidated".to_string());
                    }
                }
                RuntimeEvent::HostSessionActive { active } => {
                    self.host_session_active = active;
                    if active {
                        self.set_status("REMOTE SUPPORT SESSION ACTIVE");
                    } else if self.host_running {
                        self.set_status("Ready for another connection");
                    }
                }
                RuntimeEvent::ConnectionAuthenticated { peer, direction } => {
                    if let Some(history) = self.recent_history.as_mut() {
                        if let Err(error) = history.record(direction, &peer) {
                            self.push_log(format!("History save failed: {error}"));
                        }
                    }
                }
                RuntimeEvent::PairingCodeRevoked => {
                    self.generated_access_id = None;
                    self.code_ready_at = None;
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
                status_chip(ui,
                    if self.host_running { "Host listening" } else { "Host idle" },
                    if self.host_running { Color32::from_rgb(33, 115, 70) }
                    else { Color32::from_rgb(59, 74, 96) });
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
        let payload = build_connection_payload_bytes(&parsed.endpoint_id)?;

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
                        ui.label("Capture FPS:");
                        ui.add(egui::Slider::new(&mut self.host_fps, MIN_FPS..=MAX_FPS));
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Video max width:");
                        ui.add(egui::Slider::new(&mut self.host_max_width, 960..=1920).suffix(" px"));
                    });
                    ui.label("Lower resolution reduces latency and bandwidth. 1280 px is the recommended support setting.");
                    ui.checkbox(&mut self.host_inject_input, "Allow keyboard and mouse only after I approve the technician");
                    ui.add_space(8.0);
                    ui.label("Transport: encrypted iroh QUIC (automatic direct P2P / relay fallback)");
                    ui.label("Connection identity is generated after Start Hosting. No IP or port forwarding is normally required.");

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
                        .clicked() && !self.host_running
                    {
                        self.start_hosting_clicked();
                    }
                    if self.host_running && ui.button("Stop hosting / Revoke control").clicked() {
                        if let Err(error) = self.runtime_cmd_tx.try_send(RuntimeCommand::StopHosting) {
                            self.push_log(format!("Failed to revoke hosting: {error}"));
                        } else {
                            self.set_status("Revoking host session...");
                        }
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
                        ui.label("Public Access ID (share with technician):");
                        let mut seed_display = export_seed.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut seed_display)
                                .desired_rows(2)
                                .interactive(false)
                                .code_editor(),
                        );

                        if show_mnemonic {
                            ui.add_space(4.0);
                            ui.label("Public ID as 24 words (optional):");
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
                                    egui::Button::new("Copy Access ID")
                                        .rounding(Rounding::same(10.0))
                                        .fill(Color32::from_rgb(60, 108, 171)),
                                )
                                .clicked()
                            {
                                match copy_text_to_clipboard(&export_seed) {
                                    Ok(()) => {
                                        self.copied_notice_until =
                                            Some(Instant::now() + Duration::from_secs(2));
                                        self.set_status("Public Access ID copied to clipboard");
                                    }
                                    Err(error) => {
                                        self.push_log(format!("Clipboard copy failed: {error}"));
                                    }
                                }
                            }

                            if show_mnemonic {
                                if ui
                                    .add(
                                        egui::Button::new("Copy 24-word Public ID")
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
                                let side = ui.available_width().min(220.0).max(96.0);
                                ui.image((texture.id(), egui::vec2(side, side)));
                            });
                        }
                    });
                } else {
                    ui.label(
                        RichText::new("Click Start Hosting to generate a shareable public Access ID and QR code")
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
                    ui.label("Remote Host public Access ID / mnemonic / link:");
                    ui.add_sized(
                        [ui.available_width().max(100.0), 90.0],
                        egui::TextEdit::multiline(&mut self.access_id_input)
                            .hint_text("Paste the public Access ID copied from the remote Host"),
                    );

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
                    ui.label("Transport: iroh QUIC with automatic direct/relay negotiation");
                    ui.label("Paste the public Access ID from the remote Host, then Connect.");
                    ui.add_space(8.0);

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
                        .clicked() && !self.client_running
                    {
                        self.connect_clicked();
                    }
                    if self.client_running && ui.button("Disconnect now").clicked() {
                        if let Err(error) = self.runtime_cmd_tx.try_send(RuntimeCommand::DisconnectClient) {
                            self.push_log(format!("Disconnect request failed: {error}"));
                        } else {
                            self.set_status("Disconnecting...");
                        }
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
                        ui.label(RichText::new("Connection details").strong().size(13.0));
                        ui.horizontal_wrapped(|ui| {
                            ui.label(format!("Protocol: {}", self.telemetry_protocol));
                            if let Some(latency) = self.telemetry_latency_ms {
                                ui.label(format!("QUIC handshake: {} ms (not screen latency)", latency));
                            }
                        });
                        ui.label("Local endpoint identity:");
                        ui.add(egui::Label::new(
                            RichText::new(&self.telemetry_local_addr).monospace().size(11.0)
                        ).wrap(true));
                    });
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            for line in self.session_logs.iter().rev().take(max_lines) {
                                ui.add(egui::Label::new(RichText::new(line).size(12.5)).wrap(true));
                            }
                        });
                });
            },
        );
    }


    fn draw_code_pie(ui: &mut egui::Ui, remaining: f32) {
        let (rect, response) = ui.allocate_exact_size(
            egui::vec2(26.0, 26.0), egui::Sense::hover()
        );
        let center = rect.center();
        let painter = ui.painter();
        let bg = Color32::from_rgb(224, 233, 245);
        let fg = Color32::from_rgb(45, 113, 224);
        painter.circle_filled(center, 12.0, bg);
        let remaining = remaining.clamp(0.0, 1.0);
        if remaining > 0.0 {
            let segments = 40usize;
            let mut points = vec![center];
            let active = ((segments as f32 * remaining).ceil() as usize).max(1);
            for step in 0..=active {
                let fraction = (step as f32 / segments as f32).min(remaining);
                let angle = -std::f32::consts::FRAC_PI_2
                    + fraction * std::f32::consts::TAU;
                points.push(center + egui::vec2(angle.cos(), angle.sin()) * 12.0);
            }
            painter.add(egui::Shape::convex_polygon(points, fg, Stroke::NONE));
        }
        painter.circle_filled(center, 3.2, Color32::WHITE);
        response.on_hover_text(format!(
            "Code refresh in {} seconds",
            (remaining * 180.0).ceil() as u32,
        ));
    }

    fn draw_compact_own_code(&mut self, ui: &mut egui::Ui) {
        let ink = Color32::from_rgb(29, 50, 77);
        let muted = Color32::from_rgb(101, 120, 145);
        let elapsed = self.code_ready_at
            .map(|t| t.elapsed().as_secs_f32()).unwrap_or(180.0);
        let remaining = ((180.0 - elapsed) / 180.0).clamp(0.0, 1.0);
        let active_code = self.generated_access_id.clone()
            .filter(|_| remaining > 0.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("YOUR ID").size(10.5).strong().color(muted));
            ui.add_space(6.0);
            if let Some(code) = active_code.as_ref() {
                ui.label(RichText::new(code).size(19.5).strong().monospace().color(ink));
                ui.add_space(5.0);
                Self::draw_code_pie(ui, remaining);
                ui.add_space(4.0);
                if ui_widgets::icon_button(ui, Glyph::Copy, "Copy your temporary code").clicked() {
                    match copy_text_to_clipboard(code) {
                        Ok(()) => self.set_status("Code copied to clipboard"),
                        Err(error) => self.push_log(format!("Copy failed: {error}")),
                    }
                }
            } else {
                ui.spinner();
                ui.label(RichText::new("Refreshing ID").size(12.0).color(muted));
                if !self.host_running && ui.small_button("Retry").clicked() {
                    self.start_hosting_clicked();
                }
            }
        });
    }

    fn draw_numeric_home(&mut self, ui: &mut egui::Ui) {
        let ink = Color32::from_rgb(26, 45, 73);
        let muted = Color32::from_rgb(109, 125, 149);
        let accent = Color32::from_rgb(31, 100, 217);
        let width = ui.available_width().max(0.0);
        let card_width = width.min(450.0);
        let compact = width < 405.0;
        let padding = if compact { 15.0 } else { 24.0 };
        let content_width = (card_width - padding * 2.0).max(240.0);
        let m = ui_widgets::metrics(content_width);

        ui.add_space(if compact { 6.0 } else { 14.0 });
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("SECURE CONNECTION")
                .size(10.5).strong().color(accent));
            ui.add_space(5.0);
            ui.label(RichText::new("Connect to a computer")
                .size(if compact { 22.0 } else { 25.0 }).strong().color(ink));
            ui.add_space(5.0);
            ui.label(RichText::new("One code. Private and encrypted.")
                .size(12.0).color(muted));
        });
        ui.add_space(if compact { 12.0 } else { 19.0 });

        ui.vertical_centered(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(card_width, 0.0),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::none()
                        .fill(Color32::WHITE)
                        .stroke(Stroke::new(1.0, Color32::from_rgb(222, 231, 244)))
                        .rounding(Rounding::same(18.0))
                        .inner_margin(egui::Margin::same(padding))
                        .show(ui, |ui| {
                            ui.set_width(content_width);
                            // Every interior control uses content_width as its
                            // coordinate system, rather than the parent window.
                            ui_widgets::centered_row(ui, content_width, |ui| {
                                self.draw_compact_own_code(ui);
                            });
                            ui.add_space(13.0);
                            ui.separator();
                            ui.add_space(12.0);

                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new("REMOTE COMPUTER ID")
                                    .size(11.0).strong().color(muted));
                                ui.add_space(3.0);
                                ui.label(RichText::new(
                                    "8–10 digits · type, paste or use the keypad"
                                ).size(10.5).color(Color32::from_rgb(151, 166, 185)));
                            });
                            ui.add_space(11.0);

                            let focus = self.refocus_number_input;
                            self.refocus_number_input = false;
                            let mut submit = false;
                            ui_widgets::centered_row(ui, m.slots_width, |ui| {
                                submit = ui_widgets::code_slots(
                                    ui, &mut self.access_id_input, &mut self.numeric_cursor,
                                    focus, !self.client_running, m.slots_width,
                                ).submit;
                            });
                            ui.add_space(15.0);

                            let keys = [
                                ["1", "2", "3"], ["4", "5", "6"],
                                ["7", "8", "9"], ["Clear", "0", "Backspace"],
                            ];
                            for (row_idx, row) in keys.iter().enumerate() {
                                ui_widgets::centered_row(ui, m.keypad_width, |ui| {
                                    ui.spacing_mut().item_spacing.x = 9.0;
                                    for (col_idx, key) in row.iter().enumerate() {
                                        ui.push_id(("num_key", row_idx, col_idx), |ui| {
                                            let pressed = ui_widgets::numeric_key(
                                                ui, key, m.key_width, 46.0
                                            ).clicked();
                                            if pressed && !self.client_running {
                                                let action = match *key {
                                                    "Clear" => EditAction::Clear,
                                                    "Backspace" => EditAction::Backspace,
                                                    digit => EditAction::Digit(
                                                        digit.chars().next().unwrap_or('0')
                                                    ),
                                                };
                                                numeric_entry::apply(
                                                    &mut self.access_id_input,
                                                    &mut self.numeric_cursor, action,
                                                );
                                                self.refocus_number_input = true;
                                            }
                                        });
                                    }
                                });
                                if row_idx != 3 { ui.add_space(8.0); }
                            }
                            ui.add_space(15.0);
                            let valid = short_code::parse_code(&self.access_id_input).is_ok();
                            let enabled = valid && !self.client_running;
                            let mut connect_pressed = false;
                            ui_widgets::centered_row(ui, content_width, |ui| {
                                connect_pressed = ui_widgets::connect_button(
                                    ui, content_width, enabled,
                                ).clicked();
                            });
                            if (connect_pressed || submit) && enabled {
                                self.connect_clicked();
                            }

                            if self.client_running {
                                ui.add_space(7.0);
                                if ui.button("Cancel connection").clicked() {
                                    let _ = self.runtime_cmd_tx
                                        .try_send(RuntimeCommand::DisconnectClient);
                                }
                            }
                            ui.add_space(10.0);
                            ui.vertical_centered(|ui| {
                                ui.checkbox(&mut self.remember_this_computer,
                                    "Remember this computer if its owner also agrees");
                                ui.add_space(4.0);
                                ui.label(RichText::new(
                                    "The remote person must approve the connection."
                                ).size(11.0).color(muted));
                            });
                        });
                },
            );
        });

        let saved = self.trust_registry.saved_computers();
        if !saved.is_empty() {
            ui.add_space(14.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("SAVED COMPUTERS")
                    .size(11.0).strong().color(muted));
            });
            ui.add_space(6.0);
            for peer in saved.iter().take(8) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&peer.label).size(12.0).color(ink));
                    if ui.add_enabled(!self.client_running, egui::Button::new("Connect"))
                        .clicked() {
                        if let Err(error) = self.runtime_cmd_tx.try_send(
                            RuntimeCommand::ConnectTrusted {
                                endpoint_id: peer.endpoint_id,
                                display_name: None,
                            }
                        ) {
                            self.push_log(format!("Cannot start saved connection: {error}"));
                        } else {
                            self.client_running = true;
                            self.set_status("Connecting to trusted computer...");
                        }
                    }
                });
            }
        }
        ui.add_space(12.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(&self.status_message)
                .size(11.5).color(muted));
        });
    }

    fn draw_preferences_screen(&mut self, ui: &mut egui::Ui) {
        let ink = Color32::from_rgb(25, 45, 72);
        let muted = Color32::from_rgb(106, 123, 144);
        let width = ui.available_width().min(700.0).max(0.0);
        ui.vertical_centered(|ui| {
            ui.heading("Preferences");
            ui.label("Your support, your control.");
        });
        ui.add_space(20.0);
        ui.allocate_ui_with_layout(
            egui::vec2(width, 0.0), egui::Layout::top_down(egui::Align::Center),
            |ui| {
                egui::Frame::none().fill(Color32::WHITE)
                    .stroke(Stroke::new(1.0, Color32::from_rgb(225, 232, 241)))
                    .rounding(Rounding::same(17.0))
                    .inner_margin(egui::Margin::same(20.0))
                    .show(ui, |ui| {
                        ui.set_width((width - 40.0).max(100.0));
                        ui.heading("Input permissions");
                        ui.checkbox(&mut self.host_inject_input,
                            "Allow mouse and keyboard after an approved request");
                        ui.label(RichText::new(
                            "Changes to video/input settings take effect at the next Host session."
                        ).size(11.0).color(muted));
                        ui.add_space(15.0);
                        ui.heading("Video");
                        ui.horizontal(|ui| {
                            ui.label("Capture FPS");
                            ui.add(egui::Slider::new(&mut self.host_fps, MIN_FPS..=MAX_FPS));
                        });
                        ui.horizontal(|ui| {
                            ui.label("Video width");
                            ui.add(egui::Slider::new(&mut self.host_max_width, 960..=1920));
                        });
                        ui.add_space(17.0);
                        ui.separator();
                        ui.add_space(12.0);
                        ui.heading("Trusted devices");
                        ui.add(egui::Label::new(
                            "An enrolled technician can reconnect using its authenticated                              device identity, without another approval prompt.                              No short code, private key or password is shared."
                        ).wrap(true));
                        ui.add_space(8.0);
                        let mut allow = self.trust_registry.unattended_enabled();
                        if ui.checkbox(&mut allow,
                            "Allow unattended connections from explicitly trusted technicians"
                        ).changed() {
                            match self.trust_registry.set_unattended_enabled(allow) {
                                Ok(()) => {
                                    self.set_status(if allow {
                                        "Trusted-device access enabled"
                                    } else {
                                        "Trusted-device access disabled"
                                    });
                                    if !allow && self.host_running {
                                        let _ = self.runtime_cmd_tx
                                            .try_send(RuntimeCommand::StopHosting);
                                        self.generated_access_id = None;
                                    }
                                }
                                Err(error) => self.push_log(
                                    format!("Cannot update protected trust registry: {error}")
                                ),
                            }
                        }
                        ui.add_space(9.0);
                        let technicians = self.trust_registry.trusted_technicians();
                        if technicians.is_empty() {
                            ui.label(RichText::new("No trusted technicians")
                                .size(12.0).color(muted));
                        }
                        for technician in technicians {
                            ui.horizontal(|ui| {
                                let short_id = hex::encode(&technician.endpoint_id[..4]);
                                ui.label(RichText::new(format!(
                                    "{} · {}", technician.label, short_id
                                )).color(ink));
                                if ui.button("Revoke").clicked() {
                                    match self.trust_registry.revoke_technician(
                                        &technician.endpoint_id
                                    ) {
                                        Ok(()) => {
                                            self.set_status("Technician trust revoked");
                                            if self.host_running {
                                                // Disconnect any currently active
                                                // session, not only future sessions.
                                                let _ = self.runtime_cmd_tx.try_send(
                                                    RuntimeCommand::StopHosting
                                                );
                                            }
                                        }
                                        Err(error) => self.push_log(
                                            format!("Revocation failed: {error}")
                                        ),
                                    }
                                }
                            });
                        }
                        ui.add_space(12.0);
                        ui.heading("Remembered computers");
                        let remembered = self.trust_registry.saved_computers();
                        if remembered.is_empty() {
                            ui.label(RichText::new("No saved computers")
                                .size(12.0).color(muted));
                        }
                        for peer in remembered {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&peer.label).color(ink));
                                if ui.button("Forget").clicked() {
                                    if let Err(error) = self.trust_registry.forget_computer(
                                        &peer.endpoint_id
                                    ) {
                                        self.push_log(format!(
                                            "Cannot remove saved computer: {error}"
                                        ));
                                    } else {
                                        self.set_status("Remembered computer removed");
                                    }
                                }
                            });
                        }
                        ui.add_space(9.0);
                        ui.add(egui::Label::new(
                            RichText::new("Your private identities and trust decisions are                                 protected by Windows DPAPI for your user account.")
                                .size(11.0).color(muted)
                        ).wrap(true));
                    });
            }
        );
    }

    fn draw_history_screen(&mut self, ui: &mut egui::Ui) {
        let ink = Color32::from_rgb(27, 47, 73);
        ui.heading("Recent sessions");
        ui.label("Encrypted locally for your Windows account. No passwords or screen data.");
        ui.add_space(14.0);
        let mut bookmark: Option<(usize, bool)> = None;
        match self.recent_history.as_ref() {
            Some(archive) => {
                if archive.entries().is_empty() {
                    ui.label("No successful sessions recorded yet.");
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (index, entry) in archive.entries().iter().enumerate() {
                        ui.horizontal(|ui| {
                            let action = if entry.direction == history::Direction::Helping {
                                "Helped" } else { "Received help" };
                            ui.label(RichText::new(format!(
                                "{} · {} · {}",
                                entry.at_epoch_secs, action, entry.peer
                            )).color(ink).size(12.0));
                            if ui.button(if entry.saved { "Unsave" } else { "Save" }).clicked() {
                                bookmark = Some((index, !entry.saved));
                            }
                        });
                        ui.separator();
                    }
                });
            }
            None => { ui.label("Protected history unavailable. Check Logs."); }
        }
        if let Some((index, state)) = bookmark {
            if let Some(archive) = self.recent_history.as_mut() {
                if let Err(error) = archive.set_saved(index, state) {
                    self.push_log(format!("Cannot save history bookmark: {error}"));
                }
            }
        }
    }

    fn draw_logs_screen(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Activity log");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Copy log").clicked() {
                    let joined = self.session_logs.iter().cloned()
                        .collect::<Vec<_>>().join("\n");
                    if let Err(error) = copy_text_to_clipboard(&joined) {
                        self.push_log(format!("Cannot copy log: {error}"));
                    }
                }
            });
        });
        ui.add_space(12.0);
        egui::Frame::none().fill(Color32::WHITE)
            .stroke(Stroke::new(1.0, Color32::from_rgb(225, 232, 241)))
            .rounding(Rounding::same(16.0))
            .inner_margin(egui::Margin::same(18.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in self.session_logs.iter().rev() {
                            ui.add(egui::Label::new(
                                RichText::new(line).monospace().size(12.0))
                                .wrap(true));
                            ui.separator();
                        }
                    });
            });
    }

    fn draw_dashboard(&mut self, ui: &mut egui::Ui) {
        // The two tabs are alternative workflows. Never render both side by
        // side: on 1080p screens this overflows horizontally and hides prompts.
        ui.vertical(|ui| {
            ui.set_width(ui.available_width());
            match self.active_tab {
                ActiveTab::HostMode => {
                    self.draw_host_controls_card(ui);
                    ui.add_space(12.0);
                    self.draw_oob_exchange_card(ui);
                    ui.add_space(12.0);
                    self.draw_telemetry_card(ui, "Host connection events", 35);
                }
                ActiveTab::ClientMode => {
                    self.draw_client_request_card(ui);
                    ui.add_space(12.0);
                    self.draw_telemetry_card(ui, "Technician connection events", 35);
                }
            }
        });
    }

    fn start_hosting_clicked(&mut self) {
        let command = RuntimeCommand::StartHosting(HostRuntimeConfig {
            fps: self.host_fps,
            max_width: self.host_max_width,
            inject_input: self.host_inject_input,
            seed: self.host_seed,
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

        if let Err(error) = short_code::parse_code(access_id) {
            self.push_log(format!("Invalid numeric code: {error}"));
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
            remember_host: self.remember_this_computer,
            _transport_mode: self.host_transport_mode,
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
            let (label, fill) = match self.active_tab {
                ActiveTab::HostMode if self.host_running =>
                    ("HOST READY", Color32::from_rgb(33, 115, 70)),
                ActiveTab::ClientMode if self.client_running =>
                    ("CONNECTING / ACTIVE", Color32::from_rgb(38, 123, 92)),
                _ => ("IDLE", Color32::from_rgb(59, 74, 96)),
            };
            status_chip(ui, label, fill);
            ui.separator();
            ui.add(egui::Label::new(
                RichText::new(&self.status_message).size(12.0)
            ).truncate(true).sense(egui::Sense::hover()))
              .on_hover_text(&self.status_message);
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

        egui::Window::new("Remote support: your approval is required")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_max_width(440.0);
                ui.label(
                    RichText::new("Technician requests access to this computer")
                        .strong()
                        .size(19.0),
                );
                ui.add_space(6.0);
                ui.add(egui::Label::new(format!("Technician: {}", prompt.requester_id)).wrap(true));
                ui.add(egui::Label::new(format!("Peer identity: {}", prompt.remote_addr)).wrap(true));
                ui.add(egui::Label::new(format!("Session: {}", prompt.target_session)).wrap(true));
                ui.add_space(10.0);
                ui.add(egui::Label::new("Allow screen viewing? Keyboard and mouse control only if explicitly enabled in Host settings. You may revoke at any time.").wrap(true));
                if prompt.remember_requested {
                    ui.add_space(10.0);
                    ui.checkbox(&mut self.trust_current_technician,
                        "Trust this technician for future connections without approval");
                    ui.add(egui::Label::new(
                        "This permits the technician's authenticated computer to reconnect                          while XLINK is running. Disable or revoke in Settings."
                    ).wrap(true));
                }
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new("Deny").fill(Color32::from_rgb(128, 46, 57)))
                        .clicked()
                    {
                        match self.ui_bridge.respond_host_consent(HostConsentDecision {
                            approved: false, remember_technician: false,
                        }) {
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
                        match self.ui_bridge.respond_host_consent(HostConsentDecision {
                            approved: true,
                            remember_technician: prompt.remember_requested
                                && self.trust_current_technician,
                        }) {
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
        // Paint while pairing is pending; no external IP detection is needed.

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



        if !self.has_auto_hosted && !self.host_running {
            self.has_auto_hosted = true;
            self.start_hosting_clicked();
        }

        self.poll_runtime_events(ctx);
        // No file/QR/mnemonic import or implicit connection. Six-to-ten
        // digit keypad pairing is the only interaction path.

        // XLINK v5: a single clear home screen, not Host and Client settings pages.
        let window_focused = ctx.input(|input| input.focused);
        if window_focused && !self.window_was_focused
            && !self.show_logs && !self.show_preferences {
            self.refocus_number_input = true;
        }
        self.window_was_focused = window_focused;

        if self.code_ready_at.is_some_and(|when| when.elapsed() >= Duration::from_secs(180))
            && self.generated_access_id.is_some() {
            // Prevent copying an expired public mailbox nameplate.
            self.generated_access_id = None;
            self.code_ready_at = None;
            self.set_status("Refreshing your temporary ID...");
        }

        egui::TopBottomPanel::top("home_navigation")
            .frame(egui::Frame::none()
                .fill(Color32::WHITE)
                .inner_margin(egui::Margin::symmetric(20.0, 14.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("XLINK")
                            .size(24.0).strong().color(Color32::from_rgb(28, 64, 119)))
                            .frame(false)
                    ).on_hover_text("Home").clicked() {
                        self.show_logs = false;
                        self.show_preferences = false;
                        self.show_history = false;
                        self.refocus_number_input = true;
                    }
                    if self.host_session_active {
                        ui.label(RichText::new("●  LIVE SUPPORT")
                            .strong().size(11.0).color(Color32::from_rgb(190, 51, 65)));
                    } else if ui.available_width() > 430.0 {
                        ui.label(RichText::new("Remote support")
                            .size(12.0).color(Color32::from_rgb(106, 123, 142)));
                    }
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.host_running {
                                if ui_widgets::toolbar_button(
                                    ui, Glyph::Stop, "Stop sharing", false, true,
                                ).on_hover_text("Revoke remote access immediately").clicked() {
                                    if self.runtime_cmd_tx.try_send(
                                        RuntimeCommand::StopHosting
                                    ).is_ok() {
                                        self.generated_access_id = None;
                                        self.code_ready_at = None;
                                        self.set_status("Stopping all remote sessions...");
                                    }
                                }
                            } else if ui_widgets::toolbar_button(
                                ui, Glyph::Connect, "Start hosting", false, false,
                            ).clicked() {
                                self.start_hosting_clicked();
                            }
                            if ui.add(
                                egui::Button::new("Recent")
                                    .fill(if self.show_history {
                                        Color32::from_rgb(225, 235, 251)
                                    } else {
                                        Color32::from_rgb(246, 249, 253)
                                    })
                                    .rounding(Rounding::same(10.0))
                            ).clicked() {
                                self.show_history = !self.show_history;
                                self.show_logs = false;
                                self.show_preferences = false;
                                if !self.show_history { self.refocus_number_input = true; }
                            }
                            if ui_widgets::toolbar_button(
                                ui, Glyph::Logs, "Logs", self.show_logs, false,
                            ).clicked() {
                                self.show_logs = !self.show_logs;
                                self.show_preferences = false;
                                self.show_history = false;
                                if !self.show_logs {
                                    self.refocus_number_input = true;
                                }
                            }
                            if ui_widgets::toolbar_button(
                                ui, Glyph::Settings, "Settings", self.show_preferences, false,
                            ).clicked() {
                                self.show_preferences = !self.show_preferences;
                                self.show_logs = false;
                                self.show_history = false;
                                if !self.show_preferences {
                                    self.refocus_number_input = true;
                                }
                            }
                        });
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(Color32::from_rgb(248, 250, 253))
                .inner_margin(egui::Margin::symmetric(
                    if ctx.available_rect().width() < 580.0 { 10.0 } else { 24.0 },
                    16.0,
                )))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.show_preferences {
                            self.draw_preferences_screen(ui);
                        } else if self.show_logs {
                            self.draw_logs_screen(ui);
                        } else if self.show_history {
                            self.draw_history_screen(ui);
                        } else {
                            self.draw_numeric_home(ui);
                        }
                    });
            });

        self.draw_copy_notice(ctx);
        self.draw_client_permission_prompt(ctx);
        self.draw_host_consent_prompt(ctx);

        ctx.request_repaint_after(Duration::from_millis(UI_REPAINT_MS));
    }
}

fn apply_modern_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    visuals.window_fill = Color32::WHITE;
    visuals.panel_fill = Color32::from_rgb(248, 250, 253);
    visuals.faint_bg_color = Color32::from_rgb(245, 248, 252);
    visuals.extreme_bg_color = Color32::WHITE;
    visuals.hyperlink_color = Color32::from_rgb(39, 104, 218);
    visuals.selection.bg_fill = Color32::from_rgb(198, 221, 255);
    visuals.widgets.active.bg_fill = Color32::from_rgb(222, 235, 254);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(237, 244, 255);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(11.0, 8.0);
    style.visuals.window_rounding = Rounding::same(16.0);
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
    trust_registry: trusted::TrustRegistry,
) {
    let host_running = Arc::new(AtomicBool::new(false));
    let client_running = Arc::new(AtomicBool::new(false));
    let mut host_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut client_task: Option<tokio::task::JoinHandle<()>> = None;

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
                let registry = trust_registry.clone();

                host_task = Some(tokio::spawn(async move {
                    let _ = event_tx.send(RuntimeEvent::HostLifecycle { running: true }).await;
                    let _ = event_tx
                        .send(RuntimeEvent::SessionStatus(
                            "Host runtime started".to_string(),
                        ))
                        .await;

                    let run_result =
                        run_server_session(config, event_tx.clone(), bridge, registry).await;

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
                }));
            }
            RuntimeCommand::ConnectWithAccessId {
                access_id,
                display_name,
                remember_host,
                _transport_mode: _,
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

                let _validated_code = match short_code::parse_code(&access_id) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        client_running.store(false, Ordering::Release);
                        let _ = runtime_event_tx
                            .send(RuntimeEvent::Error(format!(
                                "invalid short pairing code: {error}"
                            )))
                            .await;
                        continue;
                    }
                };

                let event_tx = runtime_event_tx.clone();
                let client_running_flag = Arc::clone(&client_running);
                let registry = trust_registry.clone();
                let bridge = Arc::clone(&ui_bridge);

                client_task = Some(tokio::spawn(async move {
                    let _ = event_tx
                        .send(RuntimeEvent::ClientLifecycle { running: true })
                        .await;
                    let _ = event_tx
                        .send(RuntimeEvent::SessionStatus(
                            "Client runtime connecting".to_string(),
                        ))
                        .await;

                    let run_result = async {
                        let _ = event_tx.send(RuntimeEvent::SessionStatus(
                            "Authenticating short code through public mailbox...".to_string()
                        )).await;
                        let invitation = short_code::resolve(&access_id).await
                            .context("public pairing failed")?;
                        let _ = event_tx.send(RuntimeEvent::SessionStatus(
                            "Identity verified; starting encrypted QUIC connection".to_string()
                        )).await;
                        run_client_session(
                            invitation, display_name, event_tx.clone(), bridge,
                            registry, remember_host,
                        ).await
                    }.await;

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
                }));
            }
            RuntimeCommand::ConnectTrusted { endpoint_id, display_name } => {
                if client_running.compare_exchange(
                    false, true, Ordering::AcqRel, Ordering::Acquire
                ).is_err() {
                    let _ = runtime_event_tx.send(RuntimeEvent::Error(
                        "A client session is already running".to_string()
                    )).await;
                    continue;
                }
                let event_tx = runtime_event_tx.clone();
                let running_flag = Arc::clone(&client_running);
                let bridge = Arc::clone(&ui_bridge);
                let registry = trust_registry.clone();
                client_task = Some(tokio::spawn(async move {
                    let _ = event_tx.send(RuntimeEvent::ClientLifecycle {
                        running: true
                    }).await;
                    let _ = event_tx.send(RuntimeEvent::SessionStatus(
                        "Authenticating remembered computer via stable QUIC identity".into()
                    )).await;
                    let invitation = short_code::Invitation {
                        endpoint_id,
                        ticket: TRUSTED_SESSION_MARKER.to_string(),
                    };
                    let result = run_client_session(
                        invitation, display_name, event_tx.clone(), bridge, registry, false
                    ).await;
                    running_flag.store(false, Ordering::Release);
                    let _ = event_tx.send(RuntimeEvent::ClientLifecycle {
                        running: false
                    }).await;
                    if let Err(error) = result {
                        let _ = event_tx.send(RuntimeEvent::Error(
                            format!("Trusted connection failed: {error}")
                        )).await;
                    }
                }));
            }
            RuntimeCommand::RunDiagnostics => {
                let event_tx = runtime_event_tx.clone();
                tokio::spawn(async move {
                    let (topology, public_addr) = run_diagnostics(0).await;
                    let _ = event_tx.send(RuntimeEvent::DiagnosticsCompleted { topology, public_addr }).await;
                });
            }
            RuntimeCommand::StopHosting => {
                if let Some(task) = host_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                host_running.store(false, Ordering::Release);
                ui_bridge.clear_host_consent_sender();
                let _ = runtime_event_tx.send(RuntimeEvent::HostLifecycle { running: false }).await;
                let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus("Host session revoked".into())).await;
            }
            RuntimeCommand::DisconnectClient => {
                if let Some(task) = client_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                client_running.store(false, Ordering::Release);
                ui_bridge.clear_client_permission_sender();
                let _ = runtime_event_tx.send(RuntimeEvent::ClientLifecycle { running: false }).await;
                let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus("Client disconnected".into())).await;
            }
        }
    }
}

#[derive(Clone)]
pub struct PacketSender(Arc<tokio::sync::Mutex<SendStream>>);

impl PacketSender {
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        let mut guard = self.0.lock().await;
        send_message_limited(&mut *guard, msg, MAX_CONTROL_MESSAGE_BYTES).await
    }
}

#[derive(Clone)]
pub struct FrameSender(Arc<tokio::sync::Mutex<SendStream>>);

impl FrameSender {
    pub async fn send_frame(&self, frame: &FramePacket) -> Result<()> {
        let mut guard = self.0.lock().await;
        send_message(&mut *guard, frame).await
    }
}

#[derive(Clone)]
pub struct PacketReceiver(Arc<tokio::sync::Mutex<RecvStream>>);

impl PacketReceiver {
    pub async fn recv_control(&self) -> Result<ControlMessage> {
        let mut guard = self.0.lock().await;
        recv_message_limited::<ControlMessage>(&mut *guard, MAX_CONTROL_MESSAGE_BYTES).await
    }
}

#[derive(Clone)]
pub struct FrameReceiver(Arc<tokio::sync::Mutex<RecvStream>>);

impl FrameReceiver {
    pub async fn recv_frame(&self) -> Result<FramePacket> {
        let mut guard = self.0.lock().await;
        recv_message::<FramePacket>(&mut *guard).await
    }
}

async fn run_server_session(
    config: HostRuntimeConfig,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
    trust_registry: trusted::TrustRegistry,
) -> Result<()> {
    let fps = config.fps.clamp(MIN_FPS, MAX_FPS);
    if fps != config.fps {
        warn!(requested_fps = config.fps, fps, "fps value clamped to supported range");
    }

    // The private endpoint identity stays local; only its PUBLIC part is
    // exchanged in an authenticated Magic Wormhole pairing.
    let (secret_key, _) = derive_keys_from_seed(&config.seed);
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![nexus_network::NEXUS_ALPN.to_vec()])
        .bind()
        .await.context("failed to bind encrypted iroh endpoint")?;
    let node_id = endpoint.id();

    'host_pairing: loop {
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let pairing = short_code::advertise_and_pair(
            *node_id.as_bytes(), &ready_tx,
        );
        tokio::pin!(pairing);
        // Never display a randomly fabricated local code: wait for the
        // publicly operated mailbox to confirm a real allocated nameplate.
        let code = tokio::select! {
            value = ready_rx.recv() => value.context("public mailbox closed before allocation")?,
            outcome = &mut pairing => {
                outcome?;
                bail!("public pairing ended without publishing a code")
            }
        };

        let _ = runtime_event_tx.send(RuntimeEvent::HostReady {
            advertised_addr: format!("iroh:{}", node_id),
            fingerprint: node_id.to_string(),
            session_id: "one-time-secret".to_string(),
            access_id: code,
            fps,
            inject_input: config.inject_input,
        }).await;

        // Both access paths use the same authenticated QUIC endpoint:
        // a short-code SPAKE2 pairing, or a previously enrolled technician
        // authenticating with its stable, DPAPI-protected private identity.
        enum Route {
            OneTime(short_code::Invitation),
            Trusted(nexus_network::Connection),
        }
        let route = loop {
            tokio::select! {
            pairing_result = &mut pairing => {
                match pairing_result {
                    Ok(invitation) => break Route::OneTime(invitation),
                    Err(error) => {
                        warn!(?error, "public mailbox pairing failed; requesting fresh code");
                        let _ = runtime_event_tx.send(RuntimeEvent::PairingCodeRevoked).await;
                        let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
                            format!("Pairing unavailable: {error}; refreshing code")
                        )).await;
                        time::sleep(Duration::from_secs(3)).await;
                        continue 'host_pairing;
                    }
                }
            }
            incoming = accept_connection(&endpoint) => {
                match incoming {
                    Ok(connection) => {
                        let key = *connection.remote_id().as_bytes();
                        if !trust_registry.trusts_technician(&key) {
                            warn!(remote = %connection.remote_id(),
                                "rejected unsolicited QUIC connection: no trusted enrollment");
                            connection.close(4u32.into(), b"not an enrolled technician");
                            // Do not allow an untrusted peer to reach Host approval
                            // or share its screen by exploiting the numeric mailbox.
                            continue;
                        }
                        break Route::Trusted(connection)
                    }
                    Err(error) => {
                        warn!(?error, "incoming QUIC handshake rejected");
                        continue;
                    }
                }
            }
        }
        };

        let _ = runtime_event_tx.send(RuntimeEvent::PairingCodeRevoked).await;
        let (credentials, accepted) = match route {
            Route::OneTime(invitation) => (
                SessionCredentials { session_id: invitation.ticket },
                None,
            ),
            Route::Trusted(connection) => (
                SessionCredentials { session_id: TRUSTED_SESSION_MARKER.to_string() },
                Some(connection),
            ),
        };
        let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
            "Authenticated technician connecting; checking device authorization".to_string()
        )).await;
        let result = run_host_peer_session(
            &endpoint, &config, &credentials, &runtime_event_tx, &ui_bridge, fps,
            accepted, &trust_registry,
        ).await;
        let _ = runtime_event_tx.send(RuntimeEvent::HostSessionActive {
            active: false
        }).await;
        match result {
            Ok(()) => {
                let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
                    "Support session ended; generating fresh short code".to_string()
                )).await;
            }
            Err(error) => {
                warn!(?error, "support session ended with error");
                let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
                    format!("Session ended: {error}; refreshing short code")
                )).await;
            }
        }
    }
}

async fn run_host_peer_session(
    endpoint: &iroh::Endpoint,
    config: &HostRuntimeConfig,
    credentials: &SessionCredentials,
    runtime_event_tx: &mpsc::Sender<RuntimeEvent>,
    ui_bridge: &Arc<UiBridge>,
    fps: u16,
    preconnected: Option<nexus_network::Connection>,
    trust_registry: &trusted::TrustRegistry,
) -> Result<()> {
    let session_state = Arc::new(SessionStateMachine::new());
    session_state.transition(SessionState::Authenticating)?;

    // Accept QUIC connection via iroh
    // Waiting for a user-initiated connection is normal idle time, not a timeout.
    let connection = match preconnected {
        Some(connection) => connection,
        None => accept_connection(endpoint).await?,
    };
    let remote_id = *connection.remote_id().as_bytes();
    let remote_addr_str = format!("iroh:{}", connection.remote_id());

    let handshake_latency = 0u128; // iroh establishes connection in background
    let _ = runtime_event_tx.send(RuntimeEvent::ConnectionEstablished {
        protocol: "iroh".to_string(),
        local_addr: format!("iroh:{}", endpoint.id()),
        latency_ms: handshake_latency,
    }).await;

    let quic_conn_to_close = Some(connection.clone());

    let (control_s, control_r) = time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await.context("control stream handshake timed out")?
        .context("client did not open a control stream")?;
    let frame_s = connection
        .open_uni()
        .await
        .context("failed to open frame stream")?;

    let control_send = PacketSender(Arc::new(tokio::sync::Mutex::new(control_s)));
    let control_recv = PacketReceiver(Arc::new(tokio::sync::Mutex::new(control_r)));
    let frame_stream_send = FrameSender(Arc::new(tokio::sync::Mutex::new(frame_s)));

    let incoming_auth = time::timeout(HANDSHAKE_TIMEOUT, wait_for_auth_request(&control_recv))
        .await.context("authentication request timed out")??;

    runtime_event_tx
        .send(RuntimeEvent::IncomingSession {
            remote_addr: remote_addr_str.clone(),
            requester_id: incoming_auth.requester_id.clone(),
            target_session: incoming_auth.target_id.clone(),
        })
        .await
        .ok();

    let authorized_trusted = incoming_auth.target_id == TRUSTED_SESSION_MARKER
        && trust_registry.trusts_technician(&remote_id);
    if !authorized_trusted
        && credentials.verify(&incoming_auth.target_id).is_err()
    {
        let auth_error = SecurityError::AuthenticationFailed;
        let _ = session_state.transition(SessionState::Rejected);
        error!(
            ?auth_error,
            remote = %remote_addr_str,
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
            c.close(1u32.into(), b"authentication failed");
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

    let client_approved = time::timeout(Duration::from_secs(210), wait_for_client_access_decision(&control_recv))
        .await.context("remote permission decision timed out")??;
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
            c.close(3u32.into(), b"client denied access request");
        }
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

    session_state.transition(SessionState::PendingConsent)?;

    let decision = if authorized_trusted {
        let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
            format!("Trusted technician {} connected; use Stop Sharing to revoke",
                incoming_auth.requester_id)
        )).await;
        HostConsentDecision { approved: true, remember_technician: false }
    } else {
        request_host_consent(
            remote_addr_str.clone(), &incoming_auth, &runtime_event_tx, &ui_bridge,
        ).await?
    };
    let approved = decision.approved;

    if approved && !authorized_trusted && incoming_auth.remember_device
        && decision.remember_technician {
        // Both sides opted in; the peer identity is authenticated by QUIC.
        // Only successful persistence can enable future unattended access.
        let display_label: String = incoming_auth.requester_id.chars()
            .take(40).collect();
        match trust_registry.add_technician(remote_id, &display_label)
            .and_then(|_| trust_registry.set_unattended_enabled(true)) {
            Ok(()) => {
                control_send.send_control(&ControlMessage::Ack(
                    "xlink-trusted-enrollment-confirmed-v1".to_string()
                )).await?;
                let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
                    "Technician explicitly trusted. Revoke in Settings at any time.".into()
                )).await;
            }
            Err(error) => warn!(?error, "cannot save approved technician securely"),
        }
    }

    control_send.send_control(&ControlMessage::SessionConsent { approved })
        .await.context("failed to send session consent result")?;

    if !approved {
        let _ = session_state.transition(SessionState::Rejected);
        error!(
            requester_id = %incoming_auth.requester_id,
            remote = %remote_addr_str,
            error = %SecurityError::UserConsentDenied,
            "SECURITY: local user denied consent"
        );
        if let Some(ref c) = quic_conn_to_close {
            c.close(2u32.into(), b"user denied consent");
        }
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

    session_state.transition(SessionState::Active)?;
    let _ = runtime_event_tx.send(RuntimeEvent::HostSessionActive {
        active: true
    }).await;
    let _ = runtime_event_tx.send(RuntimeEvent::ConnectionAuthenticated {
        peer: format!("technician:{}", hex::encode(&remote_id[..6])),
        direction: history::Direction::ReceivingHelp,
    }).await;

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

    let live_fps = Arc::new(AtomicU16::new(fps));
    let live_fps_for_control = Arc::clone(&live_fps);
    let session_state_for_control = Arc::clone(&session_state);
    let input_for_control = Arc::clone(&input);
    let inject_input = config.inject_input;
    let control_send_clone = control_send.clone();
    let mut control_task = AbortOnDrop(tokio::spawn(async move {
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
                            tracing::debug!(
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

                    // Do not flood the control channel with acknowledgements for
                    // every mouse movement. QUIC already provides reliable delivery.
                }
                Ok(ControlMessage::ReleaseAllInputs) => {
                    if session_state_for_control.is_active() {
                        input_for_control.release_all();
                    }
                }
                Ok(ControlMessage::SetTargetFps { fps }) => {
                    if session_state_for_control.is_active() && (1..=60).contains(&fps) {
                        live_fps_for_control.store(fps, Ordering::Release);
                        info!(requested_fps = fps, "technician adjusted video rate");
                    } else {
                        warn!(fps, "ignored unauthorized or invalid FPS request");
                    }
                }
                Ok(ControlMessage::MouseButtonEvent { button, pressed }) => {
                    if !session_state_for_control.is_active() || !inject_input {
                        warn!(button, pressed, "blocked mouse click without active authorized control");
                        continue;
                    }
                    if let Err(error) = input_for_control.inject_mouse_button(button, pressed) {
                        warn!(?error, button, pressed, "mouse click injection failed");
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
    }));

    let mut capturer = ScreenCapturer::new()?;
    let mut control_task_finished = false;
    let mut capture_failures = 0u32;
    let mut pacer = adaptive::AdaptiveFrameRate::new(fps);
    let mut last_requested_fps = fps;
    let mut delta_encoder = delta::DeltaEncoder::new();
    let mut video_sequence = 0u64;
    let mut last_video_packet = Instant::now();
    let mut stats_started = Instant::now();
    let mut stats_full = 0u64;
    let mut stats_rect = 0u64;
    let mut stats_tiles = 0u64;
    let mut stats_keepalive = 0u64;
    let mut stats_idle_ticks = 0u64;
    let mut stats_bytes = 0u64;
    let mut stats_max_send_ms = 0u128;
    let mut ticker = time::interval(pacer.interval());
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            _ = &mut control_task.0 => {
                control_task_finished = true;
                info!("control stream ended; shutting down screen capture");
                break;
            }
        }

        if !session_state.is_active() {
            error!(
                state = ?session_state.state(),
                "SECURITY: blocked frame transmission while session not active"
            );
            continue;
        }

        let new_fps = live_fps.load(Ordering::Acquire);
        if last_requested_fps != new_fps {
            last_requested_fps = new_fps;
            pacer.set_requested(new_fps);
            ticker = time::interval(pacer.interval());
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        }

        let started = Instant::now();
        let frame = match capturer.capture_changed_frame() {
            Ok(frame) => {
                capture_failures = 0;
                frame
            }
            Err(error) => {
                capture_failures = capture_failures.saturating_add(1);
                if capture_failures == 1 || capture_failures % 20 == 0 {
                    warn!(?error, capture_failures, "desktop capture failed; attempting recovery");
                }
                if capture_failures % 3 == 0 {
                    if let Ok(recreated) = ScreenCapturer::new() {
                        capturer = recreated;
                    }
                }
                if capture_failures >= 600 {
                    return Err(anyhow!("desktop capture could not recover after 600 attempts"));
                }
                time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let maybe_packet = if let Some(frame) = frame {
            // Stable size preserves spatial delta coordinates between captures.
            let width_limit = (config.max_width as u32).clamp(960, 1920);
            let mut frame = frame_codec::fit_desktop(frame, width_limit, width_limit * 5 / 8)?;
            frame.frame_index = video_sequence;
            delta_encoder.encode(frame)?
        } else {
            None
        };
        let packet = match maybe_packet {
            Some(packet) => packet,
            None if last_video_packet.elapsed() >= Duration::from_secs(10) => {
                // No changed desktop pixels: keep QUIC alive with a tiny
                // header rather than duplicating a full image.
                delta::DeltaEncoder::heartbeat(video_sequence)
            }
            None => {
                stats_idle_ticks += 1;
                continue;
            }
        };
        video_sequence = video_sequence.wrapping_add(1);
        last_video_packet = Instant::now();

        match time::timeout(Duration::from_secs(8), frame_stream_send.send_frame(&packet)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                info!(?error, "frame stream ended");
                break;
            }
            Err(_) => {
                warn!("frame send stalled for 8s; closing session instead of building infinite latency");
                break;
            }
        }

        match packet.stride {
            1 => stats_rect += 1,
            2 => stats_keepalive += 1,
            3 => stats_tiles += 1,
            _ => stats_full += 1,
        }
        stats_bytes += packet.pixels.len() as u64;
        stats_max_send_ms = stats_max_send_ms.max(started.elapsed().as_millis());
        if stats_started.elapsed() >= Duration::from_secs(5) {
            let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(format!(
                "Video {}fps: key={} patch={} tiles={} idle={} keepalive={} transmitted={} KiB peak-frame={}ms",
                pacer.current(), stats_full, stats_rect, stats_tiles, stats_idle_ticks,
                stats_keepalive, stats_bytes / 1024, stats_max_send_ms,
            ))).await;
            stats_started = Instant::now();
            stats_full = 0;
            stats_rect = 0;
            stats_tiles = 0;
            stats_keepalive = 0;
            stats_idle_ticks = 0;
            stats_bytes = 0;
            stats_max_send_ms = 0;
        }
        if pacer.observe(started.elapsed()) {
            info!(fps = pacer.current(), "adaptive frame pacing updated");
            ticker = time::interval(pacer.interval());
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        }
        tracing::debug!(sequence = packet.sequence, bytes = packet.pixels.len(), "sent frame");
    }

    input.set_state(InputSessionState::Inactive);
    let _ = session_state.transition(SessionState::Terminated);
    if let Some(ref c) = quic_conn_to_close {
        c.close(0u32.into(), b"server shutdown");
    }
    if !control_task_finished {
        control_task.0.abort();
        let _ = (&mut control_task.0).await;
    }
    Ok(())
}

async fn run_client_session(
    invitation: short_code::Invitation,
    display_name: Option<String>,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
    trust_registry: trusted::TrustRegistry,
    remember_host: bool,
) -> Result<()> {
    let remote_id = iroh::PublicKey::from_bytes(&invitation.endpoint_id)
        .context("connection ID is not a valid endpoint public key")?;
    let session_id = invitation.ticket;

    // Create client endpoint
    let endpoint = create_client_endpoint_with_secret(
        SecretKey::from_bytes(&trust_registry.technician_seed()?),
    ).await?;

    // N0 provides endpoint discovery, NAT traversal and managed relay fallback.
    // Avoid pinning a guessed relay hostname that may not be the host's actual home relay.
    let handshake_start = Instant::now();
    let mut last_connect_error = String::from("no connection attempt completed");
    let mut connection = None;
    for attempt in 0..3u32 {
        let target_addr = EndpointAddr::new(remote_id.clone());
        match time::timeout(HANDSHAKE_TIMEOUT, connect_to_peer(&endpoint, target_addr)).await {
            Ok(Ok(connected)) => {
                connection = Some(connected);
                break;
            }
            Ok(Err(error)) => last_connect_error = error.to_string(),
            Err(_) => last_connect_error = "P2P/relay connection timed out".to_string(),
        }
        warn!(attempt = attempt + 1, error = %last_connect_error, "peer connection attempt failed");
        if attempt < 2 {
            time::sleep(Duration::from_secs(1u64 << attempt)).await;
        }
    }
    let connection = connection.ok_or_else(|| anyhow!(
        "failed to establish P2P/relay connection after three attempts: {last_connect_error}"
    ))?;
    let remote_addr_str = format!("iroh:{}", connection.remote_id());

    let handshake_latency = handshake_start.elapsed().as_millis();
    let _ = runtime_event_tx.send(RuntimeEvent::ConnectionEstablished {
        protocol: "iroh".to_string(),
        local_addr: format!("iroh:{}", endpoint.id()),
        latency_ms: handshake_latency,
    }).await;

    let quic_conn_to_close = Some(connection.clone());

    let run_result = async move {
        let (control_s, control_r) = time::timeout(HANDSHAKE_TIMEOUT, connection.open_bi())
            .await.context("opening control stream timed out")?
            .context("failed to open control stream")?;
        // QUIC streams become visible to the peer only when data is sent.
        // Do not wait for video before Hello/AuthRequest: the host awaits
        // that control stream and will send video only after human consent.
        let control_send = PacketSender(Arc::new(tokio::sync::Mutex::new(control_s)));
        let control_recv = PacketReceiver(Arc::new(tokio::sync::Mutex::new(control_r)));

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
                target_id: session_id.clone(),
                remember_device: remember_host,
            },
        )
        .await?;

        time::timeout(HANDSHAKE_TIMEOUT, wait_for_auth_result(&control_recv))
            .await.context("waiting for host authentication timed out")??;

        let requested_session_id = time::timeout(HANDSHAKE_TIMEOUT, wait_for_access_request(&control_recv))
            .await.context("waiting for access request timed out")??;
        if requested_session_id != session_id {
            bail!("host requested an unexpected session identity");
        }

        // The technician's explicit Connect click is the local permission
        // to REQUEST service, not permission to control the remote machine.
        // Requiring a second self-approval dialog here delays the real
        // remote consent prompt and makes a healthy connection look hung.
        // The remote Host MUST still grant on-screen SessionConsent.
        control_send.send_control(&ControlMessage::AccessDecision { approved: true })
            .await.context("failed to request remote host approval")?;
        let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
            "Connected to Host; waiting for approval on the REMOTE computer".to_string()
        )).await;

        session_state.transition(SessionState::PendingConsent)?;

        let enrollment_confirmed = time::timeout(
            Duration::from_secs(210), wait_for_session_consent(&control_recv)
        ).await.context("waiting for host consent timed out")??;
        session_state.transition(SessionState::Active)?;
        let _ = runtime_event_tx.send(RuntimeEvent::ConnectionAuthenticated {
            peer: format!("host:{}", hex::encode(&invitation.endpoint_id[..6])),
            direction: history::Direction::Helping,
        }).await;
        if enrollment_confirmed && remember_host {
            // A successful encrypted QUIC session AND an explicit Host
            // enrollment acknowledgement are required before saving a device.
            let friendly_label = format!(
                "Computer {}", hex::encode(&invitation.endpoint_id[..3])
            );
            match trust_registry.remember_computer(
                invitation.endpoint_id, &friendly_label,
            ) {
                Ok(()) => {
                    let _ = runtime_event_tx.send(RuntimeEvent::SessionStatus(
                        "This Host is now saved as a trusted computer".to_string()
                    )).await;
                }
                Err(error) => warn!(?error, "failed to remember this Host securely"),
            }
        }

        // The server has received approval and can now start streaming video.
        let frame_r = time::timeout(Duration::from_secs(45), connection.accept_uni())
            .await.context("approved session did not start its video stream")?
            .context("server failed to provide a video stream")?;
        let frame_recv = FrameReceiver(Arc::new(tokio::sync::Mutex::new(frame_r)));

        let (viewer_frame_tx, mut viewer_input_rx) =
            spawn_remote_viewer("NexusP2P - Remote Session [Active]")?;

        let session_state_for_input = Arc::clone(&session_state);
        let control_send_clone = control_send.clone();
        let event_tx_for_screenshots = runtime_event_tx.clone();
        let mut input_task = AbortOnDrop(tokio::spawn(async move {
            let mut recording: Option<actions::Recorder> = None;
            let mut saved_action_path: Option<PathBuf> = None;
            let playback_stop = Arc::new(AtomicBool::new(false));
            let mut playback_task: Option<AbortOnDrop<()>> = None;
            while let Some(event) = viewer_input_rx.recv().await {
                if !session_state_for_input.is_active() {
                    error!(
                        state = ?session_state_for_input.state(),
                        "SECURITY: blocked outbound input event while session not active"
                    );
                    continue;
                }

                // Macro playback can emit hundreds of input events, but is
                // allowed only within an explicitly authorized QUIC session.
                match &event {
                    ViewerInputEvent::ActionRecordStart => {
                        if recording.is_some() || playback_task.is_some() {
                            let _ = event_tx_for_screenshots.send(
                                RuntimeEvent::SessionStatus("Stop existing recording/replay first".into())
                            ).await;
                            continue;
                        }
                        match actions::Recorder::start() {
                            Ok(started) => {
                                recording = Some(started);
                                let _ = event_tx_for_screenshots.send(
                                    RuntimeEvent::SessionStatus(
                                        "ACTION RECORDING ACTIVE — F5 to stop".to_string()
                                    )
                                ).await;
                            }
                            Err(error) => warn!(?error, "cannot start action recorder"),
                        }
                        continue;
                    }
                    ViewerInputEvent::ActionRecordStop => {
                        if let Some(recorder) = recording.take() {
                            match recorder.finish() {
                                Ok((path, count)) => {
                                    let msg = format!(
                                        "Recorded {count} actions to {}. F6 to replay",
                                        path.display()
                                    );
                                    saved_action_path = Some(path);
                                    let _ = event_tx_for_screenshots.send(
                                        RuntimeEvent::SessionStatus(msg)
                                    ).await;
                                }
                                Err(error) => warn!(?error, "cannot finish action recording"),
                            }
                        }
                        continue;
                    }
                    ViewerInputEvent::ActionStopPlayback => {
                        playback_stop.store(true, Ordering::Release);
                        playback_task.take(); // AbortOnDrop aborts current playback.
                        let _ = control_send_clone.send_control(
                            &ControlMessage::ReleaseAllInputs
                        ).await;
                        let _ = event_tx_for_screenshots.send(
                            RuntimeEvent::SessionStatus("Action playback stopped".into())
                        ).await;
                        continue;
                    }
                    ViewerInputEvent::ActionReplay { repetitions }
                    | ViewerInputEvent::ActionReplayFile { repetitions } => {
                        if recording.is_some() {
                            let _ = event_tx_for_screenshots.send(
                                RuntimeEvent::SessionStatus(
                                    "Stop recording before replay".into()
                                )
                            ).await;
                            continue;
                        }
                        playback_stop.store(true, Ordering::Release);
                        playback_task.take();
                        let _ = control_send_clone.send_control(
                            &ControlMessage::ReleaseAllInputs
                        ).await;
                        // File-based actions are portable across XLINK machines.
                        // File dialog is explicit: do not open the last recording silently.
                        let path = if matches!(&event,
                            ViewerInputEvent::ActionReplayFile { .. }) {
                            tokio::task::spawn_blocking(|| {
                                rfd::FileDialog::new()
                                    .add_filter("XLINK actions", &["xlaction"])
                                    .pick_file()
                            }).await.unwrap_or(None)
                        } else {
                            saved_action_path.clone()
                        };
                        if let Some(path) = path {
                            if let Err(error) = actions::inspect(&path) {
                                let _ = event_tx_for_screenshots.send(
                                    RuntimeEvent::Error(format!(
                                        "Invalid action recording: {error}"
                                    ))
                                ).await;
                                continue;
                            }
                            playback_stop.store(false, Ordering::Release);
                            let stop = Arc::clone(&playback_stop);
                            let sender = control_send_clone.clone();
                            let events = event_tx_for_screenshots.clone();
                            let play_path = path.clone();
                            playback_task = Some(AbortOnDrop(tokio::spawn(async move {
                                let result = actions::replay(
                                    &play_path, *repetitions, &stop, |action| {
                                        let sender = sender.clone();
                                        async move {
                                            let message = match action {
                                                actions::Action::Move { x_norm, y_norm } =>
                                                    ControlMessage::SimulatedMouseMove {
                                                        x_norm, y_norm
                                                    },
                                                actions::Action::Button { button, pressed } =>
                                                    ControlMessage::MouseButtonEvent {
                                                        button, pressed
                                                    },
                                                actions::Action::Key { virtual_key, pressed } =>
                                                    ControlMessage::SimulatedKeyEvent {
                                                        virtual_key, pressed
                                                    },
                                            };
                                            sender.send_control(&message).await
                                        }
                                    }
                                ).await;
                                let _ = sender.send_control(
                                    &ControlMessage::ReleaseAllInputs
                                ).await;
                                let message = match result {
                                    Ok(count) => format!(
                                        "Action playback finished: {count} events"
                                    ),
                                    Err(error) => format!("Action playback failed: {error}"),
                                };
                                let _ = events.send(
                                    RuntimeEvent::SessionStatus(message)
                                ).await;
                            })));
                            let _ = event_tx_for_screenshots.send(
                                RuntimeEvent::SessionStatus(format!(
                                    "Action playback started: {} (F4 to stop)",
                                    path.display(),
                                ))
                            ).await;
                        } else {
                            let _ = event_tx_for_screenshots.send(
                                RuntimeEvent::SessionStatus(
                                    "No action file selected / recording available".into()
                                )
                            ).await;
                        }
                        continue;
                    }
                    _ => {}
                }

                let message = match event {
                    ViewerInputEvent::MouseMove { x_norm, y_norm } => {
                        ControlMessage::SimulatedMouseMove { x_norm, y_norm }
                    }
                    ViewerInputEvent::MouseButton { button, pressed } => {
                        ControlMessage::MouseButtonEvent { button, pressed }
                    }
                    ViewerInputEvent::Keyboard { virtual_key, pressed } => {
                        ControlMessage::SimulatedKeyEvent { virtual_key, pressed }
                    }
                    ViewerInputEvent::SetFrameRate(fps) => {
                        ControlMessage::SetTargetFps { fps }
                    }
                    ViewerInputEvent::ActionRecordStart
                    | ViewerInputEvent::ActionRecordStop
                    | ViewerInputEvent::ActionReplay { .. }
                    | ViewerInputEvent::ActionReplayFile { .. }
                    | ViewerInputEvent::ActionStopPlayback => continue,
                    ViewerInputEvent::ScreenshotRemote(frame) => {
                        let status = event_tx_for_screenshots.clone();
                        tokio::task::spawn_blocking(move || {
                            let msg = match screenshot::capture_remote(frame) {
                                Ok(path) => format!(
                                    "Remote screenshot saved to {} and clipboard", path.display()
                                ),
                                Err(error) => format!("Remote screenshot error: {error}"),
                            };
                            let _ = status.blocking_send(RuntimeEvent::SessionStatus(msg));
                        });
                        continue;
                    }
                    ViewerInputEvent::ScreenshotLocal => {
                        let status = event_tx_for_screenshots.clone();
                        tokio::task::spawn_blocking(move || {
                            let msg = match screenshot::capture_local() {
                                Ok(path) => format!(
                                    "Local screenshot saved to {} and clipboard", path.display()
                                ),
                                Err(error) => format!("Local screenshot error: {error}"),
                            };
                            let _ = status.blocking_send(RuntimeEvent::SessionStatus(msg));
                        });
                        continue;
                    }
                };

                if let Some(recorder) = recording.as_mut() {
                    let event = match &message {
                        ControlMessage::SimulatedMouseMove { x_norm, y_norm } =>
                            Some(actions::Action::Move {
                                x_norm: *x_norm, y_norm: *y_norm,
                            }),
                        ControlMessage::MouseButtonEvent { button, pressed } =>
                            Some(actions::Action::Button {
                                button: *button, pressed: *pressed,
                            }),
                        ControlMessage::SimulatedKeyEvent { virtual_key, pressed } =>
                            Some(actions::Action::Key {
                                virtual_key: *virtual_key, pressed: *pressed,
                            }),
                        _ => None,
                    };
                    if let Some(event) = event {
                        if let Err(error) = recorder.push(event) {
                            warn!(?error, "recording write failed; stopping capture");
                            recording.take();
                        }
                    }
                }
                if let Err(error) = control_send_clone.send_control(&message).await {
                    warn!(?error, "failed to forward viewer input event");
                    break;
                }
            }
        }));

        let control_recv_clone = control_recv.clone();
        let mut ack_task = AbortOnDrop(tokio::spawn(async move {
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
        }));

        let mut input_task_finished = false;
        let mut ack_task_finished = false;
        let mut delta_decoder = delta::DeltaDecoder::new();
        loop {
            let next_frame = tokio::select! {
                frame = time::timeout(Duration::from_secs(45), frame_recv.recv_frame()) => {
                    Some(frame.unwrap_or_else(|_| Err(anyhow!("video stream stalled for 45 seconds"))))
                },
                _ = &mut input_task.0 => {
                    input_task_finished = true;
                    None
                },
                _ = &mut ack_task.0 => {
                    ack_task_finished = true;
                    None
                },
            };
            match next_frame {
                Some(Ok(packet)) => {
                    if !session_state.is_active() {
                        error!(
                            state = ?session_state.state(),
                            sequence = packet.sequence,
                            "SECURITY: blocked inbound frame while session not active"
                        );
                        continue;
                    }

                    let frame = match delta_decoder.decode(packet) {
                        Ok(Some(frame)) => frame,
                        Ok(None) => continue, // heartbeat: no redraw and no pixels transferred
                        Err(error) => {
                            warn!(?error, "remote delta stream cannot be trusted; closing rather than showing corrupt output");
                            break;
                        }
                    };

                    match viewer_frame_tx.try_send(frame) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // Slow rendering must not accumulate full-screen frames in memory.
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            info!("viewer closed, ending client frame loop");
                            break;
                        }
                    }
                }
                Some(Err(error)) => {
                    info!(?error, "frame stream ended");
                    break;
                }
                None => {
                    info!("remote viewer or control stream ended");
                    break;
                }
            }
        }

        let _ = session_state.transition(SessionState::Terminated);
        if let Some(ref c) = quic_conn_to_close {
            c.close(0u32.into(), b"client shutdown");
        }
        if !input_task_finished {
            input_task.0.abort();
            let _ = (&mut input_task.0).await;
        }
        if !ack_task_finished {
            ack_task.0.abort();
            let _ = (&mut ack_task.0).await;
        }
        Ok(())
    }.await;

    run_result
}

async fn request_client_permission(
    server_addr: String,
    session_id: &str,
    runtime_event_tx: &mpsc::Sender<RuntimeEvent>,
    ui_bridge: &Arc<UiBridge>,
) -> Result<bool> {
    if let Ok(value) = std::env::var("NEXUS_AUTO_CLIENT_PERMISSION") {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "y") {
            warn!("NEXUS_AUTO_CLIENT_PERMISSION cannot bypass on-screen consent; ignoring auto-approval flag");
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
    remote_addr: String,
    incoming_auth: &IncomingAuth,
    runtime_event_tx: &mpsc::Sender<RuntimeEvent>,
    ui_bridge: &Arc<UiBridge>,
) -> Result<HostConsentDecision> {
    if let Ok(value) = std::env::var("NEXUS_AUTO_CONSENT") {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "y") {
            warn!("NEXUS_AUTO_CONSENT cannot bypass on-screen consent; ignoring auto-approval flag");
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "n") {
            warn!("NEXUS_AUTO_CONSENT enabled: auto-denying consent for this session");
            return Ok(HostConsentDecision { approved: false, remember_technician: false });
        }
    }

    let (decision_tx, decision_rx) = oneshot::channel();
    ui_bridge.install_host_consent_sender(decision_tx)?;

    runtime_event_tx
        .send(RuntimeEvent::HostConsentRequested {
            requester_id: incoming_auth.requester_id.clone(),
            remote_addr,
            target_session: incoming_auth.target_id.clone(),
            remember_requested: incoming_auth.remember_device,
        })
        .await
        .ok();

    match time::timeout(Duration::from_secs(180), decision_rx).await {
        Ok(Ok(decision)) => Ok(decision),
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
                if protocol_version != PROTOCOL_VERSION || role != "client" {
                    bail!("unsupported client protocol version or peer role");
                }
                saw_hello = true;
            }
            Ok(ControlMessage::AuthRequest {
                requester_id,
                target_id,
                remember_device,
            }) => {
                if !saw_hello {
                    bail!("client sent authentication request before protocol hello");
                }
                return Ok(IncomingAuth {
                    requester_id,
                    target_id,
                    remember_device,
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

async fn wait_for_session_consent(control_recv: &PacketReceiver) -> Result<bool> {
    let mut enrollment_confirmed = false;
    loop {
        match control_recv.recv_control().await {
            Ok(ControlMessage::SessionConsent { approved }) => {
                if approved {
                    info!(enrollment_confirmed, "host approved session request");
                    return Ok(enrollment_confirmed);
                }
                return Err(SecurityError::UserConsentDenied)
                    .context("host denied user consent");
            }
            Ok(ControlMessage::Ack(text)) => {
                if text == "xlink-trusted-enrollment-confirmed-v1" {
                    enrollment_confirmed = true;
                } else {
                    info!(%text, "host acknowledgement while waiting for consent");
                }
            }
            Ok(other) => {
                warn!(?other, "unexpected packet while waiting for consent");
            }
            Err(error) => {
                return Err(error).context("failed while waiting for session consent");
            }
        }
    }
}

async fn send_message<T: Serialize>(stream: &mut SendStream, value: &T) -> Result<()> {
    send_message_limited(stream, value, MAX_MESSAGE_BYTES).await
}

async fn send_message_limited<T: Serialize>(stream: &mut SendStream, value: &T, limit: usize) -> Result<()> {
    let payload = bincode::serialize(value).context("failed to encode message")?;
    if payload.len() > limit {
        bail!(
            "encoded message exceeds max size: {} > {} bytes",
            payload.len(),
            limit
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
    recv_message_limited(stream, MAX_MESSAGE_BYTES).await
}

async fn recv_message_limited<T: DeserializeOwned>(stream: &mut RecvStream, limit: usize) -> Result<T> {
    let mut len_buf = [0_u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("failed to read message length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > limit {
        bail!(
            "incoming message exceeds max size: {} > {} bytes",
            len,
            limit
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

fn default_advertise_addr(port: u16) -> SocketAddr {
    let ip = detect_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    SocketAddr::new(ip, port)
}

fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}


async fn run_diagnostics(_port: u16) -> (NetworkTopology, Option<String>) {
    // Do not report a fabricated NAT type or public address to technicians.
    // P2P discovery is handled by iroh; this panel remains unknown until
    // an actual topology probe is implemented and validated.
    (NetworkTopology::Undetermined, None)
}

fn derive_session_id(endpoint_id: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"nexus-p2p-session-v2");
    hasher.update(endpoint_id);
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn derive_keys_from_seed(seed: &[u8; 32]) -> (SecretKey, String) {
    let secret_key = SecretKey::from_bytes(seed);
    let session_id = derive_session_id(secret_key.public().as_bytes());
    (secret_key, session_id)
}

fn build_access_id(seed: &[u8; 32]) -> Result<String> {
    // Share the public endpoint identity, NEVER the host's Ed25519 private seed.
    let endpoint_id = *SecretKey::from_bytes(seed).public().as_bytes();
    let payload = AccessIdPayload {
        protocol_version: 2,
        endpoint_id,
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

    if payload.protocol_version != 2 {
        bail!("unsupported access code format; regenerate the code on the host");
    }
    iroh::PublicKey::from_bytes(&payload.endpoint_id)
        .context("access code contains invalid public endpoint identity")?;
    Ok(ParsedAccessId {
        endpoint_id: payload.endpoint_id,
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
        build_connection_payload_bytes(&parsed.endpoint_id)?
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
        parse_connection_payload_bytes(&bytes)?;
        return Ok(URL_SAFE_NO_PAD.encode(&bytes));
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

fn build_connection_payload_bytes(endpoint_id: &[u8; 32]) -> Result<Vec<u8>> {
    iroh::PublicKey::from_bytes(endpoint_id).context("invalid endpoint identity")?;
    Ok(endpoint_id.to_vec())
}

fn parse_connection_payload_bytes(payload: &[u8]) -> Result<ParsedAccessId> {
    if payload.len() != CONNECTION_PAYLOAD_BYTES {
        bail!(
            "compact seed must be {} bytes, got {}",
            CONNECTION_PAYLOAD_BYTES,
            payload.len()
        );
    }

    let mut endpoint_id = [0_u8; 32];
    endpoint_id.copy_from_slice(payload);
    iroh::PublicKey::from_bytes(&endpoint_id).context("invalid endpoint public key")?;

    Ok(ParsedAccessId { endpoint_id })
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

    #[test]
    fn ui_owned_runtime_keeps_command_dispatch_alive() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::runtime::Builder;
        use tokio::sync::{mpsc, oneshot};

        // Reproduces the previous lifecycle bug: a Handle alone does not own
        // a Runtime. The GUI must hold an Arc<Runtime> after setup returns.
        let runtime = Arc::new(Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("Tokio runtime"));
        let (commands_tx, mut commands_rx) = mpsc::channel::<u8>(1);
        let (response_tx, response_rx) = oneshot::channel();
        runtime.spawn(async move {
            if let Some(value) = commands_rx.recv().await {
                let _ = response_tx.send(value);
            }
        });

        let gui_runtime_owner = Arc::clone(&runtime);
        drop(runtime); // Simulate returning from the eframe creator closure.
        assert!(commands_tx.blocking_send(7).is_ok(), "dispatch receiver died");
        let received = gui_runtime_owner.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), response_rx).await
        }).expect("runtime task timed out").expect("dispatcher response closed");
        assert_eq!(received, 7);
    }

    #[test]
    fn access_id_roundtrip() {
        let seed = [42_u8; 32];

        let token = build_access_id(&seed).expect("build access ID");
        let parsed = parse_access_id(&token).expect("parse access ID");

        assert_eq!(
            parsed.endpoint_id,
            *iroh::SecretKey::from_bytes(&seed).public().as_bytes()
        );
    }

    #[test]
    fn exported_codes_do_not_reveal_host_secret_seed() {
        let secret = [42u8; 32];
        let access = build_access_id(&secret).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(&access).unwrap();
        assert!(!decoded.windows(32).any(|window| window == secret));
        let parsed = parse_connection_seed(&access).unwrap();
        assert_ne!(parsed.endpoint_id, secret);
        assert_eq!(
            parsed.endpoint_id,
            *iroh::SecretKey::from_bytes(&secret).public().as_bytes()
        );
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
        let seed = [7_u8; 32];

        let endpoint_id = *iroh::SecretKey::from_bytes(&seed).public().as_bytes();
        let payload = build_connection_payload_bytes(&endpoint_id)
            .expect("build compact connection payload");
        let seed_b64 = URL_SAFE_NO_PAD.encode(&payload);

        let parsed = parse_connection_seed(&seed_b64).expect("parse base64 connection seed");
        assert_eq!(parsed.endpoint_id, endpoint_id);

        let deep_link = format!("nexus://connect/{seed_b64}");
        let parsed_from_link =
            parse_connection_seed(&deep_link).expect("parse deep-link connection seed");
        assert_eq!(parsed_from_link.endpoint_id, endpoint_id);
    }

    #[test]
    fn connection_seed_roundtrip_supports_mnemonic() {
        let seed = [255_u8; 32];

        let endpoint_id = *iroh::SecretKey::from_bytes(&seed).public().as_bytes();
        let payload = build_connection_payload_bytes(&endpoint_id)
            .expect("build compact connection payload");
        let mnemonic =
            encode_connection_seed_mnemonic(&payload).expect("encode mnemonic connection seed");

        let parsed = parse_connection_seed(&mnemonic).expect("parse mnemonic connection seed");
        assert_eq!(parsed.endpoint_id, endpoint_id);
    }
}
