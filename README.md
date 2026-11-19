# XLINK — Private, simple remote support

XLINK is a native Windows remote-support app built in Rust. Its goal is
deliberately simple: **open XLINK, tell a technician your temporary numeric
code, approve the request, and get help.**

> **Development status:** This is an active Draft PR, not a production-certified
> release. Automated Windows checks and physical two-machine validation are
> separate release gates.

## What users see

The light, responsive interface has one primary screen:

- A compact **Your ID** line with a copy icon and a fading circular countdown.
- One focused **8–10-digit numeric connection field** and large on-screen keypad.
- A clear **Connect securely** action.
- Optional saved computers for explicitly approved repeat access.
- **Settings** and **Logs** as top-navigation toggle views, not stacked cards.
- A permanently accessible **Stop sharing** control while listening.

The temporary code expires after approximately 180 seconds and is replaced
through a fresh public mailbox registration. Expired codes are never shown
as valid. Returning from Settings or Logs, or refocusing the window while on
Home, places keyboard focus back in the numeric entry field.

Layout keeps the keypad centered and bounds its maximum width so resizing
the window does not distort or move controls unpredictably.

## One-time connection

1. Both people open the **same XLINK version**.
2. The person receiving help reads the compact numeric code, or copies it.
3. The technician enters the digits and presses **Connect securely**.
4. The two devices authenticate the short code using the publicly operated
   Magic Wormhole mailbox/PAKE protocol and exchange ephemeral session
   credentials and the public iroh identity.
5. iroh establishes an encrypted QUIC connection, direct where possible
   or through public relay infrastructure.
6. The person receiving help **explicitly approves** screen/control access
   on that computer. No short code grants authorization by itself.

**XLINK does not operate its own rendezvous, relay, or identity server.**
An external publicly operated service may be unavailable or rate-limited;
there is no guarantee of uninterrupted service.

## Optional remembered computers

For repeat support, **both people must opt in on the initial approved
connection**:

- The technician selects **Remember this computer if its owner also agrees**.
- The recipient can additionally select **Trust this technician for future
  connections without approval** in the actual on-screen Host approval dialog.
- The application confirms enrollment over its authenticated QUIC control
  stream. Only then does the technician store the Host's permanent public
  endpoint identity.
- Future connections from that trusted technician may skip the per-session
  approval **only while the recipient is running XLINK and has enabled
  unattended access for trusted devices**.
- Settings lists enrolled technicians and saved computers, with **Revoke**,
  **Forget**, and a global toggle. Revocation stops an active Host session.
  **Stop sharing** is also available in the top navigation.

The long-lived Host and technician private identities and trust registry are
encrypted for the current Windows user with **DPAPI** and stored under
`%LOCALAPPDATA%\XLINK\trusted-v1.dpapi`. The temporary 8–10 digit pairing
code is never saved as an unattended-access credential.

A technician cannot authorize itself: enrollment requires the recipient's
explicit original approval and public-key trust decision. A remembered device
is authenticated by its cryptographic iroh identity, not by a self-reported
machine name.

If the protected identity file becomes unreadable, fail closed rather than
silently discarding the previously trusted identities. Copying the DPAPI file
to another Windows account does not transfer the private identity.

## Technical architecture

| Component | Technology |
| --- | --- |
| Native UI | Rust, eframe/egui, light responsive single-screen UI |
| Short-code pairing | Public Magic Wormhole Mailbox, SPAKE2 |
| Persistent secrets | Windows DPAPI, local per-user trust registry |
| Transport | iroh 0.98, QUIC, N0 direct discovery / relay |
| Desktop capture | Windows DXGI Desktop Duplication |
| Video | Change detection, dirty rectangles/tiles, JPEG fallback, adaptive FPS |
| Remote input | Session-gated Win32 SendInput with key/button release |
| Consent | Remote-user permission or explicitly enrolled/allowed public-key trust |
| Diagnostics | Dedicated full-screen log view with copy action |

**Protocol compatibility:** Numeric pairing plus trusted-device signaling uses
the v5 control protocol. Both peers must run the matching build. Historic
QR / mnemonic / long-code entry flows are not exposed in this UI.

## Developer setup

Prerequisites: Windows 10/11 x64 and the current stable MSVC Rust toolchain.

```powershell
cargo check --workspace --locked
cargo test --workspace --locked
cargo run --locked
cargo build --release --locked
```

The release binary is `target/release/nexus-p2p.exe`. CI uploads it as
the `nexus-p2p-windows-x64` artifact on successful Windows release builds.

For optional network validation:

```powershell
cargo test -p nexus_network --locked two_endpoints_exchange_bidirectional_data -- --ignored --nocapture
cargo test --locked public_mailbox_pairing_roundtrip -- --ignored --nocapture
```

The second test interacts with the **actual external public mailbox service**.
Run it sparingly and do not depend on it being permanently available.

## Physical acceptance and security gates

Before release, validate on at least two Windows computers on separate
networks: code rotation, wrong/expired code, direct and relay QUIC,
request approval/denial, copy and keypad entry, complete desktop viewer
and mouse/keyboard input, stop-sharing, trusted enrollment, restart,
trusted reconnect, global disable, revocation of active access, failed DPAPI
decryption, long-running sessions and UI resizing.

The initial consent test must remain the default route. No unattended
authorization can be granted merely by possession of the 8–10-digit code.

See [the comprehensive validation plan](docs/VALIDATION.md) and
[the v4 delta-video architecture](docs/PERFORMANCE_V4.md).

## Notes

- No XLINK-operated servers, tracking infrastructure or relay nodes.
- No environment variable may auto-approve ordinary one-time support.
- Optional remote audio is not implemented yet.
- The software is **not a background service**: the person receiving help
  must have XLINK running for trusted repeat connections.
