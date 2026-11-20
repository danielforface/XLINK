//! Narrow, consent-scoped file explorer rooted in the support user's
//! Downloads/XLINK-Shared folder. Arbitrary drive access is NOT granted by
//! merely approving a remote desktop session. All operations reject absolute
//! paths, symlinks, traversal, protected directories and oversized requests.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const BLOCK_BYTES: usize = 60 * 1024;
pub const MAX_PACKET_BYTES: usize = 128 * 1024;
const MAX_LIST_ENTRIES: usize = 500;
const MAX_NAME_BYTES: usize = 255;
const MAX_RELATIVE_BYTES: usize = 2048;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    List { path: String },
    Download { path: String },
    UploadBegin { path: String, size: u64, sha256: [u8; 32] },
    UploadChunk { data: Vec<u8> },
    UploadFinish,
    Delete { path: String },
    Move { from: String, to: String },
    Copy { from: String, to: String },
    Mkdir { path: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    Items { path: String, items: Vec<Item> },
    Meta { size: u64, sha256: [u8; 32] },
    Data { bytes: Vec<u8> },
    Progress { completed: u64, total: u64 },
    Done,
    Failed { reason: String },
}

pub fn share_root() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .context("Windows user profile unavailable")?;
    let path = PathBuf::from(home).join("Downloads").join("XLINK-Shared");
    fs::create_dir_all(&path).context("cannot open restricted XLINK-Shared directory")?;
    Ok(path)
}

fn validate_relative(path: &str) -> Result<PathBuf> {
    if path.len() > MAX_RELATIVE_BYTES || path.contains('\0') {
        bail!("invalid remote file path");
    }
    let mut relative = PathBuf::new();
    for part in Path::new(path).components() {
        match part {
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                if text.is_empty() || text.len() > MAX_NAME_BYTES {
                    bail!("invalid filename length");
                }
                relative.push(name);
            }
            Component::CurDir => {}
            _ => bail!("absolute paths, parent traversal and drives are forbidden"),
        }
    }
    Ok(relative)
}

pub fn rooted_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let rel = validate_relative(relative)?;
    let mut result = root.to_path_buf();
    if fs::symlink_metadata(&result).map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false) {
        bail!("shared root cannot be a symbolic link");
    }
    for component in rel.components() {
        result.push(component.as_os_str());
        match fs::symlink_metadata(&result) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("symbolic link traversal is forbidden");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot inspect remote file path"),
        }
    }
    Ok(result)
}

fn reject_root(root: &Path, path: &Path) -> Result<()> {
    if root == path { bail!("operation on share root is forbidden"); }
    Ok(())
}

pub fn list(root: &Path, path: &str) -> Result<Vec<Item>> {
    let dir = rooted_path(root, path)?;
    if !dir.is_dir() { bail!("selected directory is not present"); }
    let mut entries = Vec::new();
    for result in fs::read_dir(dir)? {
        let entry = result?;
        let meta = entry.symlink_metadata()?;
        if meta.file_type().is_symlink() { continue; }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.len() > MAX_NAME_BYTES { continue; }
        entries.push(Item {
            name, is_dir: meta.is_dir(), size: if meta.is_file() { meta.len() } else { 0 },
        });
        if entries.len() >= MAX_LIST_ENTRIES { break; }
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir)
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(entries)
}

pub fn delete(root: &Path, path: &str) -> Result<()> {
    let target = rooted_path(root, path)?;
    reject_root(root, &target)?;
    if target.is_dir() {
        // Explicitly remove one directory only when empty: no recursive
        // deletion behind the user's back.
        fs::remove_dir(target).context("directory must be empty to delete")?;
    } else {
        fs::remove_file(target).context("failed to delete selected file")?;
    }
    Ok(())
}

pub fn move_item(root: &Path, from: &str, to: &str) -> Result<()> {
    let source = rooted_path(root, from)?;
    let target = rooted_path(root, to)?;
    reject_root(root, &source)?;
    reject_root(root, &target)?;
    if target.exists() { bail!("destination already exists; refusing overwrite"); }
    fs::rename(source, target).context("file move failed")?;
    Ok(())
}

pub fn copy_item(root: &Path, from: &str, to: &str) -> Result<()> {
    let source = rooted_path(root, from)?;
    let target = rooted_path(root, to)?;
    reject_root(root, &source)?;
    reject_root(root, &target)?;
    if !source.is_file() { bail!("only individual files can be copied"); }
    let mut reader = File::open(source)?;
    let mut writer = OpenOptions::new().write(true).create_new(true).open(target)?;
    std::io::copy(&mut reader, &mut writer)?;
    writer.flush()?;
    Ok(())
}

pub fn create_folder(root: &Path, path: &str) -> Result<()> {
    let target = rooted_path(root, path)?;
    reject_root(root, &target)?;
    fs::create_dir(&target).context("folder already exists or parent missing")?;
    Ok(())
}

pub fn hash_file(root: &Path, path: &str) -> Result<(u64, [u8; 32])> {
    let path = rooted_path(root, path)?;
    if !path.is_file() { bail!("requested file does not exist"); }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = vec![0u8; BLOCK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        length += read as u64;
        hash.update(&buffer[..read]);
    }
    Ok((length, hash.finalize().into()))
}

pub struct Upload {
    path: PathBuf,
    temporary: PathBuf,
    file: File,
    expected: u64,
    actual: u64,
    checksum: [u8; 32],
    hash: Sha256,
}
impl Upload {
    pub fn new(root: &Path, path: &str, size: u64, sha256: [u8; 32]) -> Result<Self> {
        let target = rooted_path(root, path)?;
        reject_root(root, &target)?;
        if target.exists() { bail!("destination exists; overwrite not allowed"); }
        let parent = target.parent().context("missing upload destination parent")?;
        if !parent.is_dir() { bail!("destination folder does not exist"); }
        let temp = target.with_extension(format!("xlink-{:016x}.part", rand::random::<u64>()));
        let file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        Ok(Self {
            path: target, temporary: temp, file,
            expected: size, actual: 0, checksum: sha256, hash: Sha256::new(),
        })
    }

    pub fn append(&mut self, data: &[u8]) -> Result<u64> {
        if data.is_empty() || data.len() > BLOCK_BYTES
            || self.actual.saturating_add(data.len() as u64) > self.expected {
            bail!("invalid or excessive upload block");
        }
        self.file.write_all(data)?;
        self.hash.update(data);
        self.actual += data.len() as u64;
        Ok(self.actual)
    }

    pub fn finish(self) -> Result<()> {
        if self.actual != self.expected || self.hash.finalize().as_slice() != self.checksum {
            bail!("upload length or SHA-256 verification failed");
        }
        self.file.sync_all()?;
        fs::rename(&self.temporary, &self.path).context("unable to commit received file")?;
        Ok(())
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        // Partial transfers never become visible as the destination file.
        let _ = fs::remove_file(&self.temporary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_reject_escape_and_root_deletion() {
        let root = std::env::temp_dir().join(format!("xlink-share-{}",rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        for bad in ["../secret", "/Windows/System32", "C:\\Windows", "child/../../root"] {
            assert!(rooted_path(&root,bad).is_err(), "allowed {bad}");
        }
        assert!(delete(&root,"").is_err());
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn verified_upload_never_overwrites_existing_file() {
        let root = std::env::temp_dir().join(format!("xlink-share-{}",rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let bytes = b"safe file transfer".to_vec();
        let digest: [u8;32] = Sha256::digest(&bytes).into();
        let mut file = Upload::new(&root,"hello.txt",bytes.len() as u64,digest).unwrap();
        file.append(&bytes).unwrap();
        file.finish().unwrap();
        assert_eq!(fs::read(root.join("hello.txt")).unwrap(),bytes);
        assert!(Upload::new(&root,"hello.txt",bytes.len() as u64,digest).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
