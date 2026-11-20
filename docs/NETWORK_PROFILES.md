# XLINK connection infrastructure profiles (v6)

XLINK supports a **public default profile** and a **user-managed private
infrastructure profile**. This feature controls the network infrastructure,
not the screen-sharing permission model. All QUIC sessions remain encrypted
and authenticated using iroh endpoint public keys; initial numeric pairing
still uses the Magic Wormhole PAKE exchange. Previously trusted technicians
remain subject to the Host's explicit allowlist and revocation controls.

## Public (default)

No setup required. The numeric 8–10-digit code is allocated using the
public Magic Wormhole mailbox, and iroh's N0 preset provides its public
discovery/NAT traversal/relay infrastructure.

This avoids operating XLINK-owned servers; it **does not mean no servers
are involved**. External services can be unavailable or rate-limited.

## Private infrastructure

In **Settings → Connection infrastructure**, select **Private servers**
and enter two *different services*:

| Field | Example | Required service |
| --- | --- | --- |
| Private pairing mailbox | `wss://mailbox.example.org/v1` | A Magic Wormhole-compatible **mailbox (rendezvous) server** offering secure WebSocket/TLS |
| Private iroh Relay | `https://relay.example.org` | An **iroh-compatible relay service** with a trusted TLS certificate |

The application validates both URL schemes and validates the iroh relay
address before saving. Windows verifies TLS certificates and server names;
the client **does not disable certificate validation** to accept an
unknown/custom server. If the server uses a private CA, distribute that CA
securely through the operating system's trusted root store.

**Configure both XLINK installations to use the same server URLs.** The
short numeric code alone does not encode a server address. After applying
a profile, the Host stops its existing listener, invalidates its old code
and requires the owner to **start hosting again**. There is no automatic
public fallback when a private server is inaccessible.

The saved profile is encrypted with Windows per-user **DPAPI** at
`%LOCALAPPDATA%\XLINK\network-v1.dpapi`; failure to decrypt an existing
profile blocks startup instead of silently switching to public infrastructure.

### Private mode network behavior

- A private **Mailbox** allocates the numeric nameplate and negotiates
  the PAKE-authenticated short-code exchange. It does not carry desktop
  video or controls.
- The iroh Endpoint uses the **Minimal** preset plus the explicitly
  configured custom relay. **N0 discovery and public N0 relays are not
  configured.** Target peer addresses include the private relay URL,
  so there is no dependency on N0 DNS/PKARR lookup.
- QUIC attempts direct P2P where achievable. When it requires a relay,
  only the configured iroh relay is available. The custom relay **may
  observe network metadata**, but it cannot decrypt session plaintext.
- The default public STUN topology check is suppressed at startup when
  the stored private profile is active.
- Switching from public to private in a running process does not undo
  public connections or diagnostics already made **before** the switch.
  For strict isolation, restart XLINK after saving the private profile.
- The actual server must speak the corresponding protocols. Simply
  pointing XLINK to an ordinary website, HTTPS proxy, TURN server or VPN
  gateway will **not** implement either protocol.

### Operational security and reliability

Private ownership is **not by itself stronger encryption**: it allows
administrators to govern DNS, access controls, logs, throughput, tenancy
and availability. Security still depends on an up-to-date, correctly
configured service, valid TLS identity, secure server administration and
client endpoint identity verification.

Ensure that each server is reachable from both networks and that the iroh
relay has working HTTPS + its required UDP/relay endpoints. Test wrong
certificate, wrong mailbox, wrong relay, code expiry, no public fallback
and multi-PC direct/relayed video before production rollout.

### Infrastructure references

- [Magic Wormhole mailbox server](https://github.com/magic-wormhole/magic-wormhole-mailbox-server)
- [iroh relays and examples](https://github.com/n0-computer/iroh)
- [Magic Wormhole mailbox protocol](https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html)

## Local testing

```powershell
cargo check --workspace --locked
cargo test --workspace --locked
cargo build --release --locked
```

Unit tests cover public/default validation, rejection of plain `ws://` and
`http://`, rejection of embedded URL credentials, custom relay URL parsing,
and DPAPI persistence. Physical testing still has to demonstrate actual
private server connectivity, automatic reconnection and revocation.
