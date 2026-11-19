# XLINK short-code pairing: public infrastructure only

**Owner requirement (2026-11-19): no XLINK-operated backend, no owned
rendezvous/registration database, and no self-hosted relay.**

## Architectural decision

User sees a **six-digit, temporary, session-scoped pairing code**. The code
is a rendezvous handle, not the trusted long-term identity or permission to
control the remote desktop.

1. Host opens XLINK and uses a known PUBLIC mailbox/rendezvous network.
2. A live six-digit code is displayed only after registration/claim succeeds.
   No fabricated code or offline-success state.
3. Technician enters six digits using an accessible numeric keypad.
4. Both peers use an authenticated pairing protocol (PAKE) and exchange
   ephemeral public transport identities. The mailbox operator cannot read
   the authenticated payloads.
5. Both sides verify the exchange is bound to the correct pairing session,
   then negotiate an encrypted iroh/QUIC connection using public discovery
   and relay infrastructure.
6. The **REMOTE human approves screen viewing and any separate input/audio
   permission**. A valid code alone never authorizes remote control.
7. Revocation immediately ends the session and invalidates its pairing code.

## Candidate public service

Magic Wormhole publishes a publicly operated mailbox server and a PAKE-based
pairing protocol; its normal codes have a numeric nameplate and a secret
component (e.g. nameplate-words). A six-digit-only XLINK UX would have to map
these six digits to an actual claimed nameplate and secret **and be tested
against the public server**. Do not assume the public provider offers a
general-purpose 6-digit ID -> public-key database or guarantees capacity/SLA.

The iroh N0/Pkarr services can resolve a **known public EndpointId** and
provide relay fallback. They do not, alone, resolve arbitrary six-digit codes
into previously unknown EndpointIds.

## Security invariants

- Six digits contain only ~20 bits; **never** treat them as cryptographic
  authentication of a permanent device. PAKE, transcript binding, explicit
  human authorization, short TTL and one pending session per Host are mandatory.
- Nameplate collisions or ambiguous mappings must fail safely; never attach
  the wrong peer by picking the first match.
- A code must not be displayed as ready until a verified external rendezvous
  claim has completed successfully.
- Maintain bounded retries, exponential backoff and real error reporting.
- Do not downgrade to plain WebSockets or public key only without fresh local
  consent. All media/control channels are authenticated end-to-end.
- Never expose a permanent private seed or allow a pairing code to serve as an
  unattended-access credential.
- Dependencies on publicly operated services may cause outages or rate limits.
  The GUI must display 'Discovery unavailable' rather than promise a session.

## Acceptance criteria before removal of legacy UI

- Two Windows machines using ONLY a 6-digit code connect via public mailbox,
  exchange bound public identities, negotiate encrypted QUIC and show a
  **real local consent dialog on the Host**.
- Wrong code, collision, replay, expired code and malicious peer cannot
  bypass consent or connect to an unintended endpoint.
- Verify that one code cannot bind two active hosts.
- A real connect/revoke/reconnect test completes on LAN and two separate NATs.
- Exact HEAD passes locked Cargo CI. Check the actual publicly operated
  provider's terms/capacity before production dependency.
- Once accepted, replace the GUI with a single minimal white/light screen,
  large local code, six-digit keypad, connect action and an optional detailed
  log drawer; remove legacy mnemonic/QR/import/export from the product path.

**Status:** design decision only, NOT a completed 6-digit pairing
implementation. Do not silently substitute the old long public-key code.
