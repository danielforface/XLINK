//! Zero-owned-server numeric pairing over the public Magic Wormhole mailbox.
//! The short code is an ephemeral SPAKE2 password/nameplate, NEVER an endpoint
//! identity and NEVER permission to control a computer.
use anyhow::{bail, Context, Result};
use magic_wormhole::{AppConfig, AppID, Code, MailboxConnection, Wormhole};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

// A publicly operated mailbox, NOT XLINK infrastructure. The mailbox only
// carries authenticated/encrypted endpoint bootstrap data, never video/input.
const PUBLIC_MAILBOX: &str = "ws://relay.magic-wormhole.io:4000/v1";
const APP_ID: &str = "io.github.danielforface.xlink.pairing.v1";
const NUMERIC_SECRET_DIGITS: usize = 6;
const MAX_CODE_DIGITS: usize = 10;
const PAIR_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invitation {
    pub endpoint_id: [u8; 32],
    pub ticket: String,
}

fn app_config() -> AppConfig<&'static str> {
    AppConfig {
        id: AppID::new(APP_ID),
        rendezvous_url: PUBLIC_MAILBOX.into(),
        app_version: "xlink-numeric-pair-v1",
    }
}

/// Format a server-allocated nameplate and 6 random secret digits as
/// 8-10 keyboard-friendly digits. 6 digits cannot safely carry both fields.
pub fn format_code(server_code: &Code) -> Result<String> {
    let plain = server_code.to_string();
    let (nameplate, password) = plain.split_once('-')
        .context("public mailbox returned an invalid nameplate")?;
    if !nameplate.bytes().all(|c| c.is_ascii_digit())
        || !password.bytes().all(|c| c.is_ascii_digit())
        || password.len() != NUMERIC_SECRET_DIGITS
        || nameplate.is_empty() || nameplate.len() > 4
    {
        bail!("public mailbox code exceeds the 10-digit display budget");
    }
    let padded_width = nameplate.len().max(2);
    Ok(format!("{:0>width$}{}", nameplate, password, width = padded_width))
}

/// Reverse the public-server nameplate/secret layout with no ambiguity.
pub fn parse_code(code: &str) -> Result<Code> {
    let digits: String = code.chars().filter(|c| *c != ' ' && *c != '-').collect();
    if !(8..=MAX_CODE_DIGITS).contains(&digits.len())
        || !digits.bytes().all(|c| c.is_ascii_digit())
    {
        bail!("enter the 8-10 digit connection code shown on the other computer");
    }
    let split = digits.len() - NUMERIC_SECRET_DIGITS;
    let nameplate = digits[..split].parse::<u32>()
        .context("invalid mailbox nameplate")?;
    if nameplate == 0 { bail!("invalid mailbox nameplate"); }
    format!("{}-{}", nameplate, &digits[split..]).parse::<Code>()
        .context("invalid public mailbox code")
}

/// Host: allocate a REAL mailbox nameplate before displaying a code. The
/// callback is called only after the public server confirms allocation.
pub async fn advertise_and_pair(
    endpoint_id: [u8; 32],
    ready_tx: &mpsc::Sender<String>,
) -> Result<Invitation> {
    let mut random = [0u8; 4];
    OsRng.fill_bytes(&mut random);
    let secret = format!("{:06}", u32::from_be_bytes(random) % 1_000_000);
    let mailbox = time::timeout(Duration::from_secs(20),
        MailboxConnection::create_with_password(
            app_config(), secret.as_str(),
        ))
        .await.context("public mailbox allocation timed out")?
        .context("public mailbox rejected connection")?;
    let code = format_code(mailbox.code())?;
    ready_tx.send(code).await.context("UI closed before pairing code arrived")?;

    // One active claim per mailbox. Each pairing gets a fresh 128-bit ticket.
    let mut wormhole = time::timeout(PAIR_TIMEOUT, Wormhole::connect(mailbox))
        .await.context("pairing timed out; regenerate the code")?
        .context("failed to authenticate short code using SPAKE2")?;

    let mut ticket_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut ticket_bytes);
    let invitation = Invitation {
        endpoint_id,
        ticket: hex::encode(ticket_bytes),
    };
    wormhole.send(bincode::serialize(&invitation)?).await
        .context("failed to securely deliver the QUIC identity")?;
    let acknowledgement = time::timeout(Duration::from_secs(12), wormhole.receive())
        .await.context("technician did not acknowledge encrypted identity")?
        .context("encrypted pairing acknowledgement failed")?;
    if acknowledgement != b"xlink-pair-ack-v1" {
        bail!("pairing transcript acknowledgement mismatch");
    }
    wormhole.close().await.context("failed to close public mailbox")?;
    Ok(invitation)
}

/// Technician: digits discover a PAKE-authenticated temporary QUIC identity.
/// A valid code alone never grants screen sharing or remote input rights.
pub async fn resolve(code: &str) -> Result<Invitation> {
    let mailbox_code = parse_code(code)?;
    let mailbox = time::timeout(Duration::from_secs(20),
        MailboxConnection::connect(app_config(), mailbox_code, false))
        .await.context("public mailbox lookup timed out")?
        .context("code expired, unavailable, or mailbox unreachable")?;
    let mut wormhole = time::timeout(Duration::from_secs(90), Wormhole::connect(mailbox))
        .await.context("secure pairing timed out")?
        .context("code authentication failed")?;
    let encrypted = time::timeout(Duration::from_secs(15), wormhole.receive())
        .await.context("Host did not provide its encrypted identity")?
        .context("failed to receive secure Host identity")?;
    let invitation: Invitation = bincode::deserialize(&encrypted)
        .context("invalid Host identity payload")?;
    if invitation.ticket.len() != 32
        || !invitation.ticket.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("Host provided an invalid temporary session ticket");
    }
    iroh::PublicKey::from_bytes(&invitation.endpoint_id)
        .context("Host provided an invalid QUIC identity")?;
    wormhole.send(b"xlink-pair-ack-v1".to_vec()).await
        .context("failed to acknowledge encrypted pairing")?;
    wormhole.close().await.context("failed to close public mailbox")?;
    Ok(invitation)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eight_to_ten_digits_only() {
        for (input, expected) in [
            ("01000001", "1-000001"),
            ("01345678", "1-345678"),
            ("123000001", "123-000001"),
            ("1234567890", "1234-567890"),
        ] {
            assert_eq!(parse_code(input).unwrap().to_string(), expected);
        }
        for invalid in ["123456", "1234567", "12345678901", "123-ABC", "00000000"] {
            assert!(parse_code(invalid).is_err(), "unexpectedly accepted {invalid}");
        }
    }

    /// Opt-in real pairing check using the PUBLIC Magic Wormhole mailbox.
    /// Does not expose screen data or access the local desktop.
    #[tokio::test]
    #[ignore = "uses publicly operated mailbox and external networking"]
    async fn public_mailbox_pairing_roundtrip() {
        let identity = *iroh::SecretKey::generate().public().as_bytes();
        let (tx, mut rx) = mpsc::channel(1);
        let host = tokio::spawn(async move {
            advertise_and_pair(identity, &tx).await.expect("public pairing host")
        });
        let code = time::timeout(Duration::from_secs(30), rx.recv())
            .await.expect("server did not allocate code").expect("server closed");
        let client = resolve(&code).await.expect("public pairing client");
        let remote = host.await.expect("host task crashed");
        assert_eq!(remote.endpoint_id, client.endpoint_id);
        assert_eq!(remote.ticket, client.ticket);
        assert!((8..=10).contains(&code.len()));
    }

    #[test]
    fn mailbox_format_roundtrip() {
        for raw in ["1-000001", "27-192837", "123-456789", "9876-012345"] {
            let parsed: Code = raw.parse().unwrap();
            let compact = format_code(&parsed).unwrap();
            assert!((8..=10).contains(&compact.len()));
            assert_eq!(parse_code(&compact).unwrap().to_string(), raw);
        }
    }
}
