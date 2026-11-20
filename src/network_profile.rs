//! Explicit user-selectable network infrastructure. Default remains free public
//! rendezvous + N0 relays. Private mode replaces BOTH with the user's own
//! TLS-verified services and never falls back to N0 public discovery.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

const VERSION: u8 = 1;
const MAX_URL: usize = 512;
pub const PUBLIC_MAILBOX: &str = "ws://relay.magic-wormhole.io:4000/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetworkMode {
    #[default]
    Public,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub mode: NetworkMode,
    pub mailbox_url: String,
    pub relay_url: String,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Public,
            mailbox_url: String::new(),
            relay_url: String::new(),
        }
    }
}

impl NetworkProfile {
    pub fn is_private(&self) -> bool { self.mode == NetworkMode::Private }

    pub fn validate(&self) -> Result<()> {
        if !self.is_private() { return Ok(()); }
        validate_service_url(&self.mailbox_url, "wss", "Mailbox")?;
        validate_service_url(&self.relay_url, "https", "iroh Relay")?;
        self.private_relay()?;
        Ok(())
    }

    pub fn mailbox(&self) -> &str {
        if self.is_private() { self.mailbox_url.trim() } else { PUBLIC_MAILBOX }
    }

    pub fn private_relay(&self) -> Result<iroh::RelayUrl> {
        if !self.is_private() {
            bail!("public profile does not use a manually pinned relay");
        }
        self.relay_url.trim().parse::<iroh::RelayUrl>()
            .context("invalid iroh Relay URL")
    }

    pub fn endpoint_builder(&self) -> Result<iroh::endpoint::Builder> {
        self.validate()?;
        if self.is_private() {
            // 'Minimal' and explicit relay mode: NO N0 DNS, pkarr, public
            // relay, or public discovery. The connection knows its relay URL
            // from the matching private profile.
            Ok(iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::custom([self.private_relay()?])))
        } else {
            Ok(iroh::Endpoint::builder(iroh::endpoint::presets::N0))
        }
    }

    pub fn target(&self, id: iroh::PublicKey) -> Result<iroh::EndpointAddr> {
        self.validate()?;
        let addr = iroh::EndpointAddr::new(id);
        Ok(if self.is_private() {
            addr.with_relay_url(self.private_relay()?)
        } else { addr })
    }

    pub fn describe(&self) -> &'static str {
        if self.is_private() { "Private infrastructure (no public fallback)" }
        else { "Public infrastructure (Magic Wormhole + N0)" }
    }

    pub fn load() -> Result<Self> {
        let path = Self::storage_path()?;
        if !path.exists() { return Ok(Self::default()); }
        let encrypted = fs::read(&path).context("failed to read private network settings")?;
        let plaintext = crate::trusted::decrypt_local_metadata(&encrypted)
            .context("network settings could not be decrypted; refusing insecure fallback")?;
        let persisted: Persisted = bincode::deserialize(&plaintext)
            .context("private network settings are damaged")?;
        if persisted.version != VERSION {
            bail!("unsupported private network settings version");
        }
        persisted.profile.validate()?;
        Ok(persisted.profile)
    }

    pub fn save(&self) -> Result<()> {
        self.validate()?;
        let path = Self::storage_path()?;
        self.save_at(&path)
    }

    fn save_at(&self, path: &Path) -> Result<()> {
        let persisted = Persisted { version: VERSION, profile: self.clone() };
        let ciphertext = crate::trusted::encrypt_local_metadata(
            &bincode::serialize(&persisted)?
        )?;
        let parent = path.parent().context("missing network settings directory")?;
        fs::create_dir_all(parent)?;
        let pending = path.with_extension("dpapi.tmp");
        fs::write(&pending, ciphertext)?;
        fs::rename(&pending, path).context("cannot commit protected network settings")?;
        Ok(())
    }

    fn storage_path() -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var_os("LOCALAPPDATA").context("Windows LOCALAPPDATA unavailable")?
        ).join("XLINK").join("network-v1.dpapi"))
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u8,
    profile: NetworkProfile,
}

fn validate_service_url(value: &str, scheme: &str, label: &str) -> Result<()> {
    let raw = value.trim();
    if raw.len() > MAX_URL || raw.len() < scheme.len() + 5
        || raw.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{label} URL has an invalid length or whitespace");
    }
    let prefix = format!("{scheme}://");
    if !raw.starts_with(&prefix) {
        bail!("{label} must use encrypted {scheme}:// (valid TLS certificate required)");
    }
    let after = &raw[prefix.len()..];
    let authority = after.split(&['/', '?', '#'][..]).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') ||
        authority.starts_with(':') || authority.ends_with(':') ||
        raw.contains('#') || raw.contains('?') ||
        raw.contains('\\') || raw.contains("..") {
        bail!("{label} URL contains an invalid authority or unsupported credentials");
    }
    if authority.parse::<std::net::IpAddr>().is_ok() {
        // An IP is acceptable only if its TLS certificate matches that IP.
    }
    if !authority.contains('.') && !authority.starts_with('[') &&
        !authority.starts_with("localhost:") && authority != "localhost" {
        bail!("{label} must specify a DNS hostname or a valid IP address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private() -> NetworkProfile {
        NetworkProfile {
            mode: NetworkMode::Private,
            mailbox_url: "wss://mailbox.example.org/v1".into(),
            relay_url: "https://relay.example.org".into(),
        }
    }

    #[test]
    fn valid_private_profile_isolates_both_components() {
        let profile = private();
        profile.validate().unwrap();
        assert_eq!(profile.mailbox(), "wss://mailbox.example.org/v1");
        assert_eq!(profile.private_relay().unwrap().to_string(), "https://relay.example.org/");
        assert_eq!(profile.describe(), "Private infrastructure (no public fallback)");
    }

    #[test]
    fn reject_weak_transport_and_embedded_credentials() {
        let cases = [
            ("ws://mailbox.example.org/v1", "https://relay.example.org"),
            ("wss://mailbox.example.org/v1", "http://relay.example.org"),
            ("wss://me:password@mailbox.example.org/v1", "https://relay.example.org"),
            ("wss://mailbox.example.org/v1#fragment", "https://relay.example.org"),
            ("wss://mailbox.example.org/v1", "https://relay.example.org?x=1"),
            ("", ""),
        ];
        for (mailbox, relay) in cases {
            let mut profile = private();
            profile.mailbox_url = mailbox.into();
            profile.relay_url = relay.into();
            assert!(profile.validate().is_err(), "accepted {mailbox}, {relay}");
        }
    }

    #[test]
    fn default_profile_remains_public_and_does_not_require_private_servers() {
        let p = NetworkProfile::default();
        p.validate().unwrap();
        assert!(!p.is_private());
        assert_eq!(p.mailbox(), PUBLIC_MAILBOX);
    }

    #[test]
    fn protected_profile_survives_restart() {
        let p = private();
        let path = std::env::temp_dir().join(format!(
            "xlink-network-{}.dpapi", rand::random::<u64>()
        ));
        p.save_at(&path).unwrap();
        let encrypted = fs::read(&path).unwrap();
        assert!(!encrypted.windows(p.mailbox_url.len()).any(|w| w == p.mailbox_url.as_bytes()));
        let data = crate::trusted::decrypt_local_metadata(&encrypted).unwrap();
        let persisted: Persisted = bincode::deserialize(&data).unwrap();
        assert_eq!(persisted.profile, p);
        fs::remove_file(path).unwrap();
    }
}
