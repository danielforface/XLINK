# XLINK — Release & Field Validation Gate

This is a *release blocker matrix*, not a claim that XLINK has passed field testing.

## Automated gate (GitHub Actions on Windows x64)

- `cargo check --workspace --locked`
- `cargo test --workspace --locked` (including codec, malformed frames and adaptive pacing)
- `cargo build --release --locked`
- Upload the exact tested release EXE as workflow artifact
- Optional network smoke: `cargo test -p nexus_network -- --ignored --nocapture`
- Optional repeated validation: `./scripts/soak-validation.ps1 -Cycles 20`

## Two-machine manual test plan

Use **two Windows 10/11 machines** with separate users. A is the remote
machine being assisted (Host tab); B is the technician (Client tab).
Both must run XLINK. The operator at A must see the request, approve it
locally, and retain an immediately accessible **Stop Hosting / Revoke
control** button. The technician is not authorized without this approval.

1. **Consent**: deny at A, assert no viewer and no SendInput. Accept
   at A, confirm viewer appears; test input with injection explicitly enabled
   at A. Refuse at B and ensure A receives no active session.
2. **Revocation**: hold Shift and Ctrl from B, then revoke from A; verify
   both keys release locally. After revoke, attempt mouse/keyboard inputs
   from B; A must remain unaffected. Repeat 20 times.
3. **Lifecycle**: end B's viewer window, close B mid-session, disconnect
   Wi-Fi at B, then reconnect using a *new approval*. A must return to an
   idle listening state after each disconnect without restarting XLINK.
4. **Transport**: repeat direct LAN, distinct home networks behind NAT,
   and a network where UDP is restricted and relay is required.
   The app's network diagnostic must not claim a NAT classification
   it has not measured.
5. **Video**: test 1080p/4K, long idle desktop, window motion, switching
   desktop resolution, lock/unlock, DPI scaling, multi-monitor and GPU
   reset/device loss. Record visual quality, CPU, memory, FPS and latency.
6. **Loss and congestion**: with network emulation, test 1%, 5%, 10%
   packet loss, 50/150/300 ms RTT and 2/10/50 Mbit/s bottlenecks.
   Verify adaptive FPS, acceptable lag, bounded memory and recovery.
7. **Soak**: each topology above needs at least one 60-minute test;
   execute 100 connect/disconnect/deny/revoke cycles and verify there
   is no persistent handle, memory or pressed-key leak.
8. **Security**: inspect exported Access ID / QR / mnemonic / .nexus
   files to confirm they contain the public endpoint identity, not the
   host's private seed. Old codes are invalid after the protocol change.
   Confirm no environment setting auto-approves remote control.
9. **Failure containment**: kill either side, suspend/resume Windows,
   and restore network. No unauthorized continued input or persistent
   unattended connection is permitted.

## Release decision

All automated steps must be green on the exact HEAD. Then all manual
consent/revocation, two-machine, direct+relay and impairment tests must
be explicitly recorded as PASS with build SHA, Windows version, GPU,
network conditions, measured median/p95 latency, memory peak, and logs.

**Production remains BLOCKED until those observations exist.**
Do not call a successful compile a certified release.
