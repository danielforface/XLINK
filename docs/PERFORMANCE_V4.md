# XLINK Protocol v4 — Change-driven desktop delivery

## Why the old path produced multi-second latency

Previously DXGI capture produced a complete BGRA desktop buffer every polling
cycle; software JPEG ran on the whole image, and an ordered QUIC stream could
accumulate slow full-screen transfers. The Host could be spending time encoding
and sending a picture even when the desktop was visually identical. The client's
two-frame *render* queue did not eliminate frames already queued in QUIC.

## Implemented in this development branch

- **DXGI change signal:** `capture_changed_frame()` returns `None` after
  `DXGI_ERROR_WAIT_TIMEOUT`; unchanged captures no longer require a full CPU
  buffer copy or re-encode.
- **Pixel differencing:** compare the captured pixels with the last captured
  canvas and do not transmit when identical.
- **Small bounding rectangle:** for localized changes, transmit only the
  changed rectangle. Very small patches choose lossless raw BGRA when JPEG
  would add overhead or destroy tiny details.
- **Sparse independent regions:** distant small changes use up to 12
  independently compressed dirty tiles in one atomic QUIC packet. Each tile
  is cropped again to its exact changed pixel bounds.
- **Whole-screen update:** use a full JPEG when dirty coverage is broad.
- **Resolution ceiling:** default 1280 px width, configurable 960–1920 px.
  The aspect ratio is retained, so normalized mouse coordinates continue to
  refer to the same physical location on the Host desktop.
- **Keepalive:** idle desktop transmits a zero-pixel heartbeat about every
  10 seconds instead of full-screen frames. Changed frames receive a new
  sequence ID; full keyframes refresh when needed after 60 seconds of activity
  or when dimensions change.
- **Decode before render drop:** each ordered patch is assembled onto the
  receiver's canvas before a composite may be discarded for a slow viewer.
  Dropping *unassembled* deltas would irreversibly corrupt the image.
- **Safety checks:** encoded dimensions, tile count, rectangle boundaries,
  monotonically increasing sequence, malformed payloads, and no-delta-before-
  keyframe are validated. Corrupt delta streams terminate rather than silently
  showing an inconsistent canvas.
- **Adaptive FPS:** end-to-end capture/encode/send time drives pacing. A send
  taking over eight seconds terminates the session rather than indefinitely
  queuing stale pictures.
- **Observability:** every active reporting interval logs keyframe count,
  rectangle packets, sparse tile packets, idle ticks, keepalives, payload
  KiB and maximum frame processing time.

## Correctness and benchmark gates

Windows unit tests exercise idle suppression, small rectangles, sparse distant
regions, heartbeat, no-keyframe rejection, dimension changes, JPEG fidelity and
adaptive pacing. A separate QUIC test uses two live iroh endpoints to exercise
ordered control-before-video transfer.

**Field performance is not certified by CI.** On two Windows PCs, record:
1. Host display resolution, chosen stream resolution and FPS.
2. LAN/direct versus internet/relay connection.
3. p50/p95 *screen motion-to-photon* latency with a visible clock/test flash
   (not merely QUIC handshake latency).
4. CPU/GPU, memory, KiB/s and input-click responsiveness during idle desktop,
   cursor movement, text editing, window drag and full-screen motion.
5. Recovery after display resolution changes, session revoke/reapproval, and
   network loss. Confirm keyboard and mouse buttons are released on revoke.
6. Compare with the previous full-frame transport on identical network paths.

### Next architectural upgrades

- Read native DXGI dirty/move rectangles to avoid CPU pixel scans on every
  changed frame and add a separate cursor-shape/position channel.
- Use GPU-based conversion/encoder when available; current JPEG is CPU-based.
- Use separate prioritized low-latency channels and frame expiry/budgeting so
  a congested video path never delays keyboard/mouse messages.
- Add packet sequence and freshness telemetry, plus sender/receiver clock
  sampling, so latency can be attributed to capture, encode, network, decode
  or render rather than inferred from the user's experience.

## Remote audio (requested; not represented as implemented)

A proper optional audio channel should use **WASAPI loopback capture**, encode
with a low-latency audio codec, and play at the technician endpoint with a small
bounded jitter buffer. It must be **off by default**, explicitly approved on
the remote machine, and immediately revoked with the screen session. Audio
permissions should not be implied by screen-view consent. Audio transport and
the corresponding UI are not yet implemented in this branch.
