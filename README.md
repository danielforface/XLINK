# NexusP2P

NexusP2P is a Windows-focused remote support engine written in Rust.

## Features

- QUIC transport with certificate fingerprint pinning
- Explicit host consent before session activation
- DXGI Desktop Duplication host capture path
- Client remote session viewer window
- Session-gated Win32 `SendInput` support (optional via CLI)

## Prerequisites

- Windows 10/11 x64
- Rust toolchain: `stable-x86_64-pc-windows-msvc`

## Development Validation

Run all tests and compile checks:

```powershell
cargo test --workspace
cargo check --workspace
```

## Running Locally

### Interactive all-in-one mode

The same executable can act as Host or Client. If you run without flags, it opens an interactive gateway:

```powershell
./dist/nexus-p2p.exe
```

You can choose:

- `1` Host session (Server)
- `2` Connect to host (Client)

Client mode prompts for target Access ID and Access Password.

### 1) Start host/server

```powershell
cargo run -- --server --port 5000 --fps 30
```

For active OS input injection on host, opt in explicitly:

```powershell
cargo run -- --server --port 5000 --fps 30 --inject-input
```

If the host is behind NAT or has multiple interfaces, set an explicit advertised endpoint:

```powershell
cargo run -- --server --port 5000 --advertise 192.168.1.42:5000
```

The server prints:

- SHA-256 certificate fingerprint
- one-time Session ID
- 6-digit Access Password
- Access ID (contains host endpoint + fingerprint + Session ID)

### 2) Start client

```powershell
cargo run -- --access-id <ACCESS_ID> --access-password <ACCESS_PASSWORD>
```

Optional custom client name:

```powershell
cargo run -- --access-id <ACCESS_ID> --access-password <ACCESS_PASSWORD> --display-name workstation-a
```

Advanced/manual mode is still supported if needed:

```powershell
cargo run -- --client 127.0.0.1:5000 --fingerprint <SERVER_FINGERPRINT> --target-id <SESSION_ID> --access-password <ACCESS_PASSWORD>
```

## Production Build

Use the packaging script:

```powershell
./scripts/build-release.ps1
```

Artifacts:

- `dist/nexus-p2p.exe`
- `dist/README.md`

## Production Test Pass

```powershell
./scripts/test-production.ps1
```

This runs `cargo check`, `cargo test`, and `cargo build --release`.
