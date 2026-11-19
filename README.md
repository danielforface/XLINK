# NexusP2P

NexusP2P is a Windows-focused remote support engine written in Rust, now powered by a modern desktop GUI built with `eframe` + `egui`.

## Features

- Modern native desktop GUI (no command prompt workflow)
- Host/Client tabbed control surface with live session telemetry
- Client Session Index history with one-click reconnect from successful sessions
- Out-of-band Access ID exchange:
  - Copy to clipboard
  - Save/load `.nexus` connection files
  - QR code generation, QR PNG export, and QR image/clipboard decoding
- QUIC transport with certificate fingerprint pinning
- ID-only connection workflow (server needs only Session ID inside Access ID)
- Explicit multi-gate permission flow:
  - Server requests client permission
  - Client approves/denies in GUI
  - Host user gives final local consent in GUI modal
- DXGI Desktop Duplication host capture
- Session-gated Win32 `SendInput` support

## Prerequisites

- Windows 10/11 x64
- Rust toolchain: `stable-x86_64-pc-windows-msvc`

## Development Validation

```powershell
cargo check --workspace
cargo test --workspace
```

## Run The GUI App

```powershell
cargo run
```

or with packaged binary:

```powershell
./dist/nexus-p2p.exe
```

The app opens directly in the desktop GUI (no CLI prompts).

## Host Workflow

1. Open `Host Mode`.
2. Set port/FPS/advertise address and click `Start Hosting`.
3. Share generated Access ID out-of-band using one of:
   - `Copy Access ID`
   - `Save Connection File`
  - `Export QR PNG`
  - QR shown in host dashboard
4. Wait for incoming session request panel and consent chain.

## Client Workflow

1. Open `Client Mode`.
2. Provide Access ID by one of:
   - Paste text
   - Load connection file
   - Load QR image
   - Decode QR from clipboard image
3. Click `Connect`.
4. Approve or deny server access request in GUI prompt.
5. Reconnect anytime by clicking a saved entry in `Session Index History`.

## Consent and security

Every control session requires interactive approval on the remote computer.
Environment flags cannot auto-approve access or bypass on-screen consent.
`NEXUS_AUTO_CLIENT_PERMISSION=0` and `NEXUS_AUTO_CONSENT=0` can
explicitly deny requests in negative-path tests, but positive approval is
always a user action.

The first hardening pass bounds the viewer's frame handoff queue to two frames,
drops excess frames instead of accumulating memory, validates incoming frame
dimensions, and caps control messages independently of video frames.

**Important:** The Windows CI build gate is a prerequisite, not a substitute
for exercising two actual Windows machines across direct and relay connections.
Do not deploy as production remote-support software until consent revocation,
viewer lifecycle, reconnection, network loss, and input release tests pass.

## Production Build

```powershell
./scripts/build-release.ps1
```

Artifacts:

- `dist/nexus-p2p.exe`
- `dist/README.md`

## Production Validation Script

```powershell
./scripts/test-production.ps1
```

This runs `cargo check`, `cargo test`, and `cargo build --release`.
