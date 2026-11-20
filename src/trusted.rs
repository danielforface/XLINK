//! Windows per-user DPAPI-protected device identity and trusted peer registry.
//! Secret identity seeds never leave this module in plaintext persistent storage.
//! A trusted peer is an authenticated QUIC public key; a numeric short code
//! never appears in the persistent trust database.
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTRY_VERSION: u32 = 1;
const MAX_TRUSTED_PEERS: usize = 64;
const MAX_LABEL: usize = 64;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 1;

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        data: *const DataBlob,
        description: *const u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *const c_void,
        flags: u32,
        result: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        data: *const DataBlob,
        description: *mut *mut u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *const c_void,
        flags: u32,
        result: *mut DataBlob,
    ) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(handle: *mut c_void) -> *mut c_void;
}

/// Encrypt arbitrary local metadata under the current Windows account.
pub fn encrypt_local_metadata(plaintext: &[u8]) -> Result<Vec<u8>> {
    dpapi(plaintext, true)
}

/// Decrypt metadata; any failure must fail closed instead of treating the
/// encrypted bytes as empty/unprotected state.
pub fn decrypt_local_metadata(ciphertext: &[u8]) -> Result<Vec<u8>> {
    dpapi(ciphertext, false)
}

fn dpapi(input: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    let mut bytes = input.to_vec();
    let blob = DataBlob {
        cb_data: bytes.len().try_into().context("protected data exceeds DPAPI limit")?,
        pb_data: bytes.as_mut_ptr(),
    };
    let mut output = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &blob, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(),
                std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output,
            )
        } else {
            CryptUnprotectData(
                &blob, std::ptr::null_mut(), std::ptr::null(),
                std::ptr::null_mut(), std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN, &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context(
            if encrypt { "Windows credential encryption failed" }
            else { "Windows credential decryption failed" }
        );
    }
    if output.pb_data.is_null() {
        bail!("Windows credential encryption returned an empty allocation");
    }
    let protected = unsafe {
        std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec()
    };
    unsafe { LocalFree(output.pb_data.cast::<c_void>()); }
    Ok(protected)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPeer {
    pub endpoint_id: [u8; 32],
    pub label: String,
    pub added_utc: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedTrust {
    version: u32,
    host_seed: [u8; 32],
    technician_seed: [u8; 32],
    unattended_enabled: bool,
    trusted_technicians: Vec<TrustedPeer>,
    saved_computers: Vec<TrustedPeer>,
}

impl PersistedTrust {
    fn new() -> Self {
        Self {
            version: REGISTRY_VERSION,
            host_seed: rand::random(),
            technician_seed: rand::random(),
            unattended_enabled: false, // Never opt in to unattended access silently.
            trusted_technicians: Vec::new(),
            saved_computers: Vec::new(),
        }
    }
    fn validate(&self) -> Result<()> {
        if self.version != REGISTRY_VERSION {
            bail!("unsupported local trust registry format");
        }
        for peers in [&self.trusted_technicians, &self.saved_computers] {
            if peers.len() > MAX_TRUSTED_PEERS {
                bail!("local trusted device list exceeds limit");
            }
            for peer in peers {
                if peer.label.len() > MAX_LABEL {
                    bail!("invalid trusted device label length");
                }
                iroh::PublicKey::from_bytes(&peer.endpoint_id)
                    .context("saved device contains invalid QUIC public identity")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TrustRegistry {
    state: Arc<Mutex<PersistedTrust>>,
    path: PathBuf,
}

impl TrustRegistry {
    pub fn load_or_create() -> Result<Self> {
        let root = std::env::var_os("LOCALAPPDATA")
            .context("Windows LOCALAPPDATA is unavailable")?;
        Self::load_or_create_at(PathBuf::from(root).join("XLINK").join("trusted-v1.dpapi"))
    }

    fn load_or_create_at(path: PathBuf) -> Result<Self> {
        let state = if path.exists() {
            let bytes = fs::read(&path).context("cannot read protected XLINK identity")?;
            let plaintext = dpapi(&bytes, false)?;
            let persisted: PersistedTrust = bincode::deserialize(&plaintext)
                .context("XLINK identity registry is corrupt or incompatible")?;
            persisted.validate()?;
            persisted
        } else {
            let state = PersistedTrust::new();
            save_state(&path, &state)?;
            state
        };
        Ok(Self { state: Arc::new(Mutex::new(state)), path })
    }

    pub fn host_seed(&self) -> Result<[u8; 32]> {
        Ok(self.state.lock().map_err(|_| anyhow!("trust registry poisoned"))?.host_seed)
    }

    pub fn technician_seed(&self) -> Result<[u8; 32]> {
        Ok(self.state.lock().map_err(|_| anyhow!("trust registry poisoned"))?.technician_seed)
    }

    pub fn unattended_enabled(&self) -> bool {
        self.state.lock().map(|s| s.unattended_enabled).unwrap_or(false)
    }

    pub fn set_unattended_enabled(&self, enabled: bool) -> Result<()> {
        self.update(|state| {
            state.unattended_enabled = enabled;
            Ok(())
        })
    }

    pub fn trusted_technicians(&self) -> Vec<TrustedPeer> {
        self.state.lock().map(|s| s.trusted_technicians.clone()).unwrap_or_default()
    }

    pub fn saved_computers(&self) -> Vec<TrustedPeer> {
        self.state.lock().map(|s| s.saved_computers.clone()).unwrap_or_default()
    }

    pub fn trusts_technician(&self, key: &[u8; 32]) -> bool {
        self.state.lock().map(|s| {
            s.unattended_enabled && s.trusted_technicians.iter()
                .any(|peer| &peer.endpoint_id == key)
        }).unwrap_or(false)
    }

    pub fn add_technician(&self, key: [u8; 32], label: &str) -> Result<()> {
        self.update(|state| add_peer(&mut state.trusted_technicians, key, label))
    }

    pub fn remember_computer(&self, key: [u8; 32], label: &str) -> Result<()> {
        self.update(|state| add_peer(&mut state.saved_computers, key, label))
    }

    pub fn revoke_technician(&self, key: &[u8; 32]) -> Result<()> {
        self.update(|state| {
            state.trusted_technicians.retain(|peer| &peer.endpoint_id != key);
            Ok(())
        })
    }

    pub fn forget_computer(&self, key: &[u8; 32]) -> Result<()> {
        self.update(|state| {
            state.saved_computers.retain(|peer| &peer.endpoint_id != key);
            Ok(())
        })
    }

    fn update(&self, change: impl FnOnce(&mut PersistedTrust) -> Result<()>) -> Result<()> {
        let mut guard = self.state.lock().map_err(|_| anyhow!("trust registry poisoned"))?;
        let mut next = guard.clone();
        change(&mut next)?;
        next.validate()?;
        save_state(&self.path, &next)?;
        *guard = next;
        Ok(())
    }
}

fn add_peer(peers: &mut Vec<TrustedPeer>, key: [u8; 32], label: &str) -> Result<()> {
    iroh::PublicKey::from_bytes(&key).context("invalid peer identity")?;
    if label.len() > MAX_LABEL { bail!("device label is too long"); }
    let label = label.trim();
    let label = if label.is_empty() { "Trusted computer" } else { label };
    if let Some(existing) = peers.iter_mut().find(|peer| peer.endpoint_id == key) {
        existing.label = label.to_string();
    } else {
        if peers.len() >= MAX_TRUSTED_PEERS { bail!("too many trusted peers"); }
        peers.push(TrustedPeer {
            endpoint_id: key, label: label.to_string(),
            added_utc: SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
        });
    }
    Ok(())
}

fn save_state(path: &Path, state: &PersistedTrust) -> Result<()> {
    state.validate()?;
    let plaintext = bincode::serialize(state)?;
    let encrypted = dpapi(&plaintext, true)?;
    let directory = path.parent().context("missing credential storage directory")?;
    fs::create_dir_all(directory).context("cannot create XLINK credential directory")?;
    let staging = path.with_extension("dpapi.tmp");
    fs::write(&staging, &encrypted).context("cannot write protected credentials")?;
    fs::rename(&staging, path).context("cannot commit protected credentials")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_registry_survives_restart_without_plaintext_seeds() {
        let path = std::env::temp_dir().join(format!(
            "xlink-trust-test-{}.dpapi", rand::random::<u64>()
        ));
        let registry = TrustRegistry::load_or_create_at(path.clone()).unwrap();
        let seed = registry.host_seed().unwrap();
        assert!(!fs::read(&path).unwrap().windows(32).any(|window| window == seed));
        let restored = TrustRegistry::load_or_create_at(path.clone()).unwrap();
        assert_eq!(restored.host_seed().unwrap(), seed);
        assert_eq!(restored.unattended_enabled(), false);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_allowlist_and_revocation_are_enforced() {
        let path = std::env::temp_dir().join(format!(
            "xlink-trust-test-{}.dpapi", rand::random::<u64>()
        ));
        let registry = TrustRegistry::load_or_create_at(path.clone()).unwrap();
        let key = *iroh::SecretKey::generate().public().as_bytes();
        registry.add_technician(key, "Demo technician").unwrap();
        assert!(!registry.trusts_technician(&key));
        registry.set_unattended_enabled(true).unwrap();
        assert!(registry.trusts_technician(&key));
        registry.revoke_technician(&key).unwrap();
        assert!(!registry.trusts_technician(&key));
        fs::remove_file(path).unwrap();
    }
}
