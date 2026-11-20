//! Private recent-connection history. Stores metadata only, never session
//! secrets, public mailbox passwords, frames, clipboard or keystrokes.
use crate::trusted;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: u16 = 1;
const MAX_ENTRIES: usize = 250;
const MAX_LABEL: usize = 80;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Direction {
    Helping,
    ReceivingHelp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub at_epoch_secs: u64,
    pub peer: String,
    pub direction: Direction,
    pub title: String,
    pub saved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Archive {
    version: u16,
    entries: Vec<Entry>,
}

pub struct History {
    path: PathBuf,
    items: Vec<Entry>,
}

fn validate(entries: &[Entry]) -> Result<()> {
    if entries.len() > MAX_ENTRIES {
        bail!("connection history exceeds bounded local limit");
    }
    for e in entries {
        if e.title.len() > MAX_LABEL || e.peer.len() > MAX_LABEL {
            bail!("connection history contains oversized metadata");
        }
    }
    Ok(())
}

impl History {
    pub fn open() -> Result<Self> {
        let root = std::env::var_os("LOCALAPPDATA")
            .context("LOCALAPPDATA unavailable; cannot safely store history")?;
        Self::open_at(PathBuf::from(root).join("XLINK").join("history-v1.dpapi"))
    }

    fn open_at(path: PathBuf) -> Result<Self> {
        let items = if path.exists() {
            let ciphertext = fs::read(&path).context("cannot read session history")?;
            let plaintext = trusted::decrypt_local_metadata(&ciphertext)?;
            let archive: Archive = bincode::deserialize(&plaintext)
                .context("session history is corrupt")?;
            if archive.version != VERSION { bail!("unsupported session history version"); }
            validate(&archive.entries)?;
            archive.entries
        } else {
            Vec::new()
        };
        Ok(Self { path, items })
    }

    pub fn entries(&self) -> &[Entry] { &self.items }

    pub fn record(&mut self, direction: Direction, peer: &str) -> Result<()> {
        let title = match direction {
            Direction::Helping => "Technician session",
            Direction::ReceivingHelp => "Remote support received",
        };
        self.items.insert(0, Entry {
            at_epoch_secs: SystemTime::now().duration_since(UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            peer: peer.chars().take(MAX_LABEL).collect(),
            direction,
            title: title.to_string(),
            saved: false,
        });
        self.items.truncate(MAX_ENTRIES);
        self.persist()
    }

    pub fn set_saved(&mut self, index: usize, saved: bool) -> Result<()> {
        let entry = self.items.get_mut(index).context("history index not found")?;
        entry.saved = saved;
        self.persist()
    }

    pub fn clear(&mut self) -> Result<()> {
        self.items.clear();
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        validate(&self.items)?;
        let archive = Archive { version: VERSION, entries: self.items.clone() };
        let plaintext = bincode::serialize(&archive)?;
        let ciphertext = trusted::encrypt_local_metadata(&plaintext)?;
        let directory = self.path.parent().context("missing history folder")?;
        fs::create_dir_all(directory).context("failed to create history directory")?;
        let stage = self.path.with_extension("tmp");
        fs::write(&stage, ciphertext).context("failed to write protected history")?;
        fs::rename(stage, &self.path).context("failed to commit history")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_is_encrypted_bounded_and_restart_stable() {
        let path = std::env::temp_dir().join(format!(
            "xlink-history-{}.dpapi", rand::random::<u64>()
        ));
        let mut h = History::open_at(path.clone()).unwrap();
        h.record(Direction::Helping, "important-peer-public-identity").unwrap();
        h.set_saved(0, true).unwrap();
        let ciphertext = fs::read(&path).unwrap();
        assert!(!ciphertext.windows(13).any(|x| x == b"important-peer"));
        let h2 = History::open_at(path.clone()).unwrap();
        assert_eq!(h2.entries().len(), 1);
        assert!(h2.entries()[0].saved);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn history_limits_untrusted_metadata() {
        let mut list = vec![Entry {
            at_epoch_secs: 0, peer: "A".to_string(), direction: Direction::Helping,
            title: "B".to_string(), saved: false,
        }];
        assert!(validate(&list).is_ok());
        list[0].peer = "x".repeat(81);
        assert!(validate(&list).is_err());
    }
}
