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
- Encrypted authenticated iroh/QUIC transport with public-key endpoint identification
- Public-key-only Access ID (the Host private identity seed is never exported)
- Explicit multi-gate permission flow:
  - Server requests client permission
  - Client approves/denies in GUI
  - Host user gives final local consent in GUI modal
- DXGI Desktop Duplication host capture with JPEG compression and adaptive FPS
- Session-gated Win32 `SendInput` support with held-key release on revoke

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

1. Open `Host Mode` and explicitly start hosting.
2. Set port/FPS/advertise address and click `Start Hosting`.
3. Share generated Access ID out-of-band using one of:
   - `Copy Access ID`
   - `Save Connection File`
  - `Export QR PNG`
  - QR shown in host dashboard
4. Wait for incoming session request panel; approve the technician locally in the Host GUI.\n5. Use **Stop Hosting / Revoke control** to immediately revoke access. Hosting otherwise remains available after the technician disconnects.

## Client Workflow

1. Open `Client Mode`.
2. Provide Access ID by one of:
   - Paste text
   - Load connection file
   - Load QR image
   - Decode QR from clipboard image
3. Click `Connect`.
4. Approve or deny server access request in GUI prompt.
5. Use **Disconnect now** to end the active session. Reconnection must obtain fresh consent on the Host.\n6. Historical connection codes only remain valid while the original Host endpoint identity is active.

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

## Compatibility and release gate

This branch introduces protocol v2. **Previously exported connection seeds/files/QR and
older client versions are not compatible. Regenerate access codes with the updated Host.**
Connection codes now carry the Host public identity only, never its private key.

The live transport uses iroh endpoint discovery (direct UDP with relay fallback),
not a BitTorrent tracker or torrent file transfer protocol.

The first resilience release must satisfy [the Windows/field validation matrix](docs/VALIDATION.md).
Successful Cargo tests do not replace two-machine consent/revocation and network-impairment tests.
For repeatable local validation run `./scripts/soak-validation.ps1 -Cycles 20`.

## Windows connection troubleshooting (2026-11-19 incident)

If the status bar displays `Failed to start host runtime: channel closed`,
this is a local application-lifecycle failure, **not** a NAT or relay failure.
Earlier builds allowed the Tokio runtime to be dropped while the eframe UI
remained open. The fixed UI now holds an `Arc<Runtime>` for its entire lifetime.
Always test with the Windows executable from the most recent successful
workflow associated with the exact branch HEAD. Exit older processes first.

**Host:** open the Host tab, click **Start Hosting**, and wait for a public
Access ID in the Out-of-Band Access Exchange card. Share it with the technician
through a trusted channel using Copy, QR, or the connection file. The Access ID
contains only the Host's public endpoint identity; do not share the Host's
private runtime seed. The Host must approve the connection on-screen.

**Technician:** launch the same build of XLINK, paste the Host's Access ID in
Client Mode, click **Connect**, and respond to the prompts. The iroh/N0 service
resolves the peer's network path and can use QUIC relay fallback; this is not
BitTorrent and a successful connection depends on an operational discovery and
relay service and permitted outbound traffic. 

The transport selector, advertised IP, and hole-punch address controls from
older GUI builds were misleading because those values were unused by the
actual iroh connection implementation; they have been removed from the UI.

If you see `Host runtime failed: ...`, copy the full message; a bind or
network discovery failure must be distinguished from the previously fixed
closed-command-channel failure. The UI should show STANDBY before hosting and
Host Ready with an Access ID only after the iroh endpoint binds successfully.
