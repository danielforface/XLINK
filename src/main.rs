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
use nexus_network::{bind_client, bind_server, normalize_fingerprint_hex};
use qrcode_generator::QrCodeEcc;
use quinn::{RecvStream, SendStream, VarInt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};

const PROTOCOL_VERSION: u16 = 1;
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_PORT: u16 = 5000;
const DEFAULT_FPS: u16 = 30;
const MIN_FPS: u16 = 1;
const MAX_FPS: u16 = 60;
const ACCESS_ID_VERSION: u8 = 1;
const UI_REPAINT_MS: u64 = 16;

fn main() -> Result<()> {
    init_tracing();

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
}

#[derive(Debug, Clone)]
struct ParsedAccessId {
    server_addr: SocketAddr,
    fingerprint: String,
    target_id: String,
}

#[derive(Debug, Clone)]
struct IncomingAuth {
    requester_id: String,
    target_id: String,
}

#[derive(Debug, Clone)]
struct HostRuntimeConfig {
    port: u16,
    fps: u16,
    inject_input: bool,
    advertise_addr: Option<SocketAddr>,
}

#[derive(Debug)]
enum RuntimeCommand {
    StartHosting(HostRuntimeConfig),
    ConnectWithAccessId {
        access_id: String,
        display_name: Option<String>,
    },
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
    Error(String),
}

#[derive(Default)]
struct UiBridge {
    pending_client_permission_sender: Mutex<Option<oneshot::Sender<bool>>>,
    pending_host_consent_sender: Mutex<Option<oneshot::Sender<bool>>>,
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
}

impl NexusGuiApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        runtime_cmd_tx: mpsc::Sender<RuntimeCommand>,
        runtime_event_rx: mpsc::Receiver<RuntimeEvent>,
        ui_bridge: Arc<UiBridge>,
    ) -> Self {
        apply_modern_theme(&cc.egui_ctx);

        let host_port = DEFAULT_PORT;
        let default_advertise = default_advertise_addr(host_port).to_string();

        Self {
            active_tab: ActiveTab::HostMode,
            access_id_input: String::new(),
            generated_access_id: None,
            qr_code_texture: None,
            copied_notice_until: None,
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
                        "HOST ACTIVE"
                    } else {
                        "HOST READY"
                    },
                    if self.host_running {
                        Color32::from_rgb(48, 139, 89)
                    } else {
                        Color32::from_rgb(65, 84, 110)
                    },
                );
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

    fn draw_host_tab(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            card(
                &mut columns[0],
                "Host Session Controls",
                "Low-latency endpoint and capture configuration",
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Port:");
                        ui.add(
                            egui::DragValue::new(&mut self.host_port)
                                .clamp_range(1..=65535)
                                .speed(1),
                        );

                        ui.add_space(12.0);
                        ui.label("Capture FPS:");
                        ui.add(egui::Slider::new(&mut self.host_fps, MIN_FPS..=MAX_FPS));

                        ui.add_space(12.0);
                        ui.checkbox(&mut self.host_inject_input, "Enable host input injection");
                    });

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Advertised Address:");
                        ui.add_sized(
                            [300.0, 28.0],
                            egui::TextEdit::singleline(&mut self.host_advertise_addr_input),
                        );
                    });

                    ui.add_space(8.0);

                    let start_button_label = if self.host_running {
                        "Hosting..."
                    } else {
                        "Start Hosting"
                    };

                    if ui
                        .add_enabled(
                            !self.host_running,
                            egui::Button::new(start_button_label)
                                .rounding(Rounding::same(10.0))
                                .fill(Color32::from_rgb(42, 132, 92)),
                        )
                        .clicked()
                    {
                        self.start_hosting_clicked();
                    }
                },
            );

            columns[0].add_space(10.0);

            card(
                &mut columns[0],
                "Security Sequence",
                "Zero-trust gates before active session",
                |ui| {
                    ui.label("1. Access ID handshake and fingerprint validation");
                    ui.label("2. Server sends access request to client");
                    ui.label("3. Client approves or denies in app modal");
                    ui.label("4. Host gives final local consent in app modal");
                    ui.label("5. Session transitions to Active and streams start");
                },
            );

            card(
                &mut columns[1],
                "Out-of-Band Access Exchange",
                "Clipboard, connection files, and QR workflows",
                |ui| {
                    if let Some(access_id) = self.generated_access_id.clone() {
                        let mut read_only = access_id.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut read_only)
                                .desired_rows(4)
                                .interactive(false)
                                .code_editor(),
                        );

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
                                match copy_text_to_clipboard(&access_id) {
                                    Ok(()) => {
                                        self.copied_notice_until =
                                            Some(Instant::now() + Duration::from_secs(2));
                                        self.set_status("Access ID copied to clipboard");
                                    }
                                    Err(error) => {
                                        self.push_log(format!("Clipboard copy failed: {error}"));
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
                                match save_access_id_file(&access_id) {
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
                                match save_access_id_qr_png(&access_id) {
                                    Ok(path) => {
                                        self.set_status("QR PNG exported successfully");
                                        self.push_log(format!("Saved QR PNG to {}", path.display()));
                                    }
                                    Err(error) => {
                                        self.push_log(format!("QR PNG export failed: {error}"));
                                    }
                                }
                            }

                            if ui
                                .add(
                                    egui::Button::new("Refresh QR")
                                        .rounding(Rounding::same(10.0))
                                        .fill(Color32::from_rgb(98, 90, 132)),
                                )
                                .clicked()
                            {
                                match self.rebuild_qr_texture(ui.ctx()) {
                                    Ok(()) => self.set_status("QR code regenerated"),
                                    Err(error) => self.push_log(format!("QR refresh failed: {error}")),
                                }
                            }
                        });

                        ui.add_space(10.0);

                        if let Some(texture) = &self.qr_code_texture {
                            ui.vertical_centered(|ui| {
                                let side = 280.0;
                                ui.image((texture.id(), egui::vec2(side, side)));
                            });
                        }
                    } else {
                        ui.label(
                            RichText::new("Start hosting to generate Access ID and QR code")
                                .color(Color32::from_rgb(176, 190, 207)),
                        );
                    }
                },
            );

            columns[1].add_space(10.0);

            card(
                &mut columns[1],
                "Live Telemetry",
                "Recent runtime and handshake events",
                |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(220.0)
                        .show(ui, |ui| {
                            for line in self.session_logs.iter().rev().take(35) {
                                ui.label(RichText::new(line).size(12.5));
                            }
                        });
                },
            );
        });
    }

    fn draw_client_tab(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |columns| {
            card(
                &mut columns[0],
                "Client Access Request",
                "Import Access ID from text, file, or QR path",
                |ui| {
                    ui.label("Access ID:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.access_id_input)
                            .desired_rows(4)
                            .hint_text("Paste Access ID, load from file, or decode from QR"),
                    );

                    ui.add_space(8.0);

                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add(
                                egui::Button::new("Paste Access ID")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(60, 108, 171)),
                            )
                            .clicked()
                        {
                            match paste_text_from_clipboard() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Access ID pasted from clipboard");
                                }
                                Err(error) => {
                                    self.push_log(format!("Clipboard paste failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Load Connection File")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(80, 91, 128)),
                            )
                            .clicked()
                        {
                            match load_access_id_file() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Access ID loaded from connection file");
                                }
                                Err(error) => {
                                    self.push_log(format!("Connection file import failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Load QR Image")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(93, 88, 132)),
                            )
                            .clicked()
                        {
                            match load_access_id_from_qr_file() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Access ID decoded from QR image");
                                }
                                Err(error) => {
                                    self.push_log(format!("QR file decode failed: {error}"));
                                }
                            }
                        }

                        if ui
                            .add(
                                egui::Button::new("Decode QR From Clipboard Image")
                                    .rounding(Rounding::same(10.0))
                                    .fill(Color32::from_rgb(94, 79, 116)),
                            )
                            .clicked()
                        {
                            match load_access_id_from_clipboard_image() {
                                Ok(text) => {
                                    self.access_id_input = text;
                                    self.set_status("Access ID decoded from clipboard QR image");
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
                            [250.0, 28.0],
                            egui::TextEdit::singleline(&mut self.client_display_name)
                                .hint_text("optional"),
                        );

                        let connect_label = if self.client_running {
                            "Connecting..."
                        } else {
                            "Connect"
                        };

                        if ui
                            .add_enabled(
                                !self.client_running,
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

            columns[0].add_space(10.0);

            card(
                &mut columns[0],
                "Connection Pipeline",
                "Client-side permission and secure startup",
                |ui| {
                    ui.label("1. Parse Access ID and derive endpoint fingerprint");
                    ui.label("2. Authenticate with Session ID from Access ID payload");
                    ui.label("3. Receive server access request in modal prompt");
                    ui.label("4. Approve or deny before host local consent");
                    ui.label("5. Enter active streaming and controlled input phase");
                },
            );

            card(
                &mut columns[1],
                "Connection Telemetry",
                "Recent runtime and network events",
                |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(380.0)
                        .show(ui, |ui| {
                            for line in self.session_logs.iter().rev().take(70) {
                                ui.label(RichText::new(line).size(12.5));
                            }
                        });
                },
            );
        });
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

        if let Err(error) = parse_access_id(access_id) {
            self.push_log(format!("Access ID validation failed: {error}"));
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
                if self.host_running { "HOST RUNNING" } else { "HOST STANDBY" },
                if self.host_running {
                    Color32::from_rgb(48, 139, 89)
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
}

impl eframe::App for NexusGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_runtime_events(ctx);

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
            .show(ctx, |ui| match self.active_tab {
                ActiveTab::HostMode => self.draw_host_tab(ui),
                ActiveTab::ClientMode => self.draw_client_tab(ui),
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

                let parsed_access_id = match parse_access_id(&access_id) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        client_running.store(false, Ordering::Release);
                        let _ = runtime_event_tx
                            .send(RuntimeEvent::Error(format!(
                                "invalid access ID supplied by UI: {error}"
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
        }
    }
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
    let server = bind_server(bind_addr).await?;
    let advertised_addr = advertised_server_addr(bind_addr, config.advertise_addr);
    let credentials = SessionCredentials::generate();
    let access_id = build_access_id(
        advertised_addr,
        &server.certificate_fingerprint,
        &credentials.session_id,
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

    let session_state = Arc::new(SessionStateMachine::new());
    session_state.transition(SessionState::Authenticating)?;

    let connection = server.accept().await?;
    let remote_addr = connection.remote_address();
    let (mut control_send, mut control_recv) = connection
        .accept_bi()
        .await
        .context("client did not open a control stream")?;

    let incoming_auth = wait_for_auth_request(&mut control_recv).await?;

    runtime_event_tx
        .send(RuntimeEvent::IncomingSession {
            remote_addr,
            requester_id: incoming_auth.requester_id.clone(),
            target_session: incoming_auth.target_id.clone(),
        })
        .await
        .ok();

    if let Err(auth_error) = credentials.verify(&incoming_auth.target_id) {
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

    send_message(
        &mut control_send,
        &ControlMessage::AccessRequest {
            session_id: incoming_auth.target_id.clone(),
        },
    )
    .await
    .context("failed to send access request to client")?;

    let client_approved = wait_for_client_access_decision(&mut control_recv).await?;
    if !client_approved {
        let _ = session_state.transition(SessionState::Rejected);
        runtime_event_tx
            .send(RuntimeEvent::SessionStatus(
                "Client denied access request".to_string(),
            ))
            .await
            .ok();

        let _ = send_message(
            &mut control_send,
            &ControlMessage::SessionConsent { approved: false },
        )
        .await;

        connection.close(VarInt::from_u32(3), b"client denied access request");
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

    session_state.transition(SessionState::PendingConsent)?;

    let approved = request_host_consent(
        remote_addr,
        &incoming_auth,
        &runtime_event_tx,
        &ui_bridge,
    )
    .await?;
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
            if config.inject_input { "inject" } else { "preview" }
        )),
    )
    .await
    .context("failed to send session approval acknowledgement")?;

    let session_state_for_control = Arc::clone(&session_state);
    let input_for_control = Arc::clone(&input);
    let inject_input = config.inject_input;
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

        if let Err(error) = send_message(&mut frame_stream, &packet).await {
            info!(?error, "frame stream ended");
            break;
        }

        info!(sequence = packet.sequence, bytes = packet.pixels.len(), "sent frame");
    }

    input.set_state(InputSessionState::Inactive);
    let _ = session_state.transition(SessionState::Terminated);
    let _ = frame_stream.finish().await;
    connection.close(VarInt::from_u32(0), b"server shutdown");
    let _ = control_task.await;
    Ok(())
}

async fn run_client_session(
    parsed_access_id: ParsedAccessId,
    display_name: Option<String>,
    runtime_event_tx: mpsc::Sender<RuntimeEvent>,
    ui_bridge: Arc<UiBridge>,
) -> Result<()> {
    let client =
        bind_client(SocketAddr::from(([0, 0, 0, 0], 0)), parsed_access_id.fingerprint.clone())
            .await?;
    let connection = client.connect(parsed_access_id.server_addr, "localhost").await?;

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
            target_id: parsed_access_id.target_id.clone(),
        },
    )
    .await?;

    wait_for_auth_result(&mut control_recv).await?;

    let requested_session_id = wait_for_access_request(&mut control_recv).await?;
    let client_approved = request_client_permission(
        parsed_access_id.server_addr,
        &requested_session_id,
        &runtime_event_tx,
        &ui_bridge,
    )
    .await?;

    send_message(
        &mut control_send,
        &ControlMessage::AccessDecision {
            approved: client_approved,
        },
    )
    .await
    .context("failed to send client access decision")?;

    if !client_approved {
        let _ = session_state.transition(SessionState::Rejected);
        info!("local client denied access request");
        connection.close(VarInt::from_u32(3), b"client denied access request");
        let _ = session_state.transition(SessionState::Terminated);
        return Ok(());
    }

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
        match recv_message::<FramePacket>(&mut frame_recv).await {
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
    connection.close(VarInt::from_u32(0), b"client shutdown");
    input_task.abort();
    let _ = input_task.await;
    ack_task.abort();
    let _ = ack_task.await;
    Ok(())
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

async fn wait_for_access_request(control_recv: &mut RecvStream) -> Result<String> {
    loop {
        match recv_message::<ControlMessage>(control_recv).await {
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

async fn wait_for_client_access_decision(control_recv: &mut RecvStream) -> Result<bool> {
    loop {
        match recv_message::<ControlMessage>(control_recv).await {
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

fn save_access_id_file(access_id: &str) -> Result<std::path::PathBuf> {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name("connection.nexus")
        .add_filter("Nexus Connection", &["nexus", "txt"])
        .save_file()
    else {
        bail!("export canceled")
    };

    fs::write(&path, access_id).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
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

fn load_access_id_file() -> Result<String> {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Nexus Connection", &["nexus", "txt"])
        .pick_file()
    else {
        bail!("import canceled")
    };

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let access_id = content.trim().to_string();
    if access_id.is_empty() {
        bail!("connection file is empty")
    }

    Ok(access_id)
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
