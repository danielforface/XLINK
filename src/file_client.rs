//! Technician-side typed file protocol over a separate encrypted QUIC
//! bidirectional stream. Transfers are chunked, checked with SHA-256 and
//! never overwrite local or remote files silently.
use crate::{file_service, recv_message_limited, send_message_limited};
use anyhow::{bail, Context, Result};
use file_service::{Reply, Request};
use nexus_network::{Connection, RecvStream, SendStream};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub enum Operation {
    List(String),
    Upload { source: PathBuf, target: String },
    Download { source: String, directory: PathBuf },
    Delete(String),
    Move { from: String, to: String },
    Copy { from: String, to: String },
    Mkdir(String),
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Directory { path: String, items: Vec<file_service::Item> },
    Complete(String),
}

struct Channel {
    output: SendStream,
    input: RecvStream,
}
impl Channel {
    async fn connect(connection: &Connection) -> Result<Self> {
        let (mut output, mut input) = connection.open_bi().await
            .context("failed to open isolated QUIC file channel")?;
        send_message_limited(&mut output, &"XLINK-FILES-1", 64).await?;
        let approved: bool = recv_message_limited(&mut input, 64).await
            .context("remote file authorization failed")?;
        if !approved {
            bail!("remote computer did not approve file access for this session");
        }
        Ok(Self { output, input })
    }
    async fn request(&mut self, req: Request) -> Result<Reply> {
        send_message_limited(&mut self.output, &req, file_service::MAX_PACKET_BYTES).await?;
        let reply: Reply = recv_message_limited(&mut self.input, file_service::MAX_PACKET_BYTES).await?;
        if let Reply::Failed { reason } = &reply {
            bail!("remote file operation rejected: {reason}");
        }
        Ok(reply)
    }
}

fn compute_hash(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut input = File::open(path).context("cannot read local file for upload")?;
    let mut sha = Sha256::new();
    let mut size = 0u64;
    let mut block = vec![0u8; file_service::BLOCK_BYTES];
    loop {
        let n = input.read(&mut block)?;
        if n == 0 { break; }
        sha.update(&block[..n]);
        size += n as u64;
    }
    Ok((size, sha.finalize().into()))
}

fn next_download_name(directory: &Path, filename: &str) -> Result<PathBuf> {
    if filename.len() > 255
        || !filename.bytes().all(|b| b != b'/' && b != b'\\' && b != b':' && b != 0)
        || filename == "." || filename == ".." {
        bail!("invalid received file name");
    }
    let path = directory.join(filename);
    if !path.exists() { return Ok(path); }
    for suffix in 1..=9999 {
        let p = directory.join(format!("{filename}.xlink-{suffix}"));
        if !p.exists() { return Ok(p); }
    }
    bail!("all suggested local destination filenames are taken")
}

/// Full upload/download progress callback is invoked after every verified
/// block, so UI can show a continuous progress bar without buffering files.
pub async fn execute(
    connection: &Connection,
    operation: Operation,
    mut progress: impl FnMut(u64, u64),
) -> Result<Outcome> {
    let mut channel = Channel::connect(connection).await?;
    match operation {
        Operation::List(path) => match channel.request(Request::List { path }).await? {
            Reply::Items { path, items } => Ok(Outcome::Directory { path, items }),
            _ => bail!("unexpected remote directory reply"),
        },
        Operation::Delete(path) => {
            expect_done(channel.request(Request::Delete { path }).await?)?;
            Ok(Outcome::Complete("Remote item deleted".into()))
        }
        Operation::Move { from, to } => {
            expect_done(channel.request(Request::Move { from, to }).await?)?;
            Ok(Outcome::Complete("Remote item moved".into()))
        }
        Operation::Copy { from, to } => {
            expect_done(channel.request(Request::Copy { from, to }).await?)?;
            Ok(Outcome::Complete("Remote item copied".into()))
        }
        Operation::Mkdir(path) => {
            expect_done(channel.request(Request::Mkdir { path }).await?)?;
            Ok(Outcome::Complete("Remote folder created".into()))
        }
        Operation::Upload { source, target } => {
            let (size, hash) = compute_hash(&source)?;
            expect_done(channel.request(Request::UploadBegin {
                path: target, size, sha256: hash,
            }).await?)?;
            let mut input = File::open(&source)?;
            let mut buf = vec![0u8; file_service::BLOCK_BYTES];
            let mut count = 0u64;
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 { break; }
                let response = channel.request(Request::UploadChunk {
                    data: buf[..n].to_vec()
                }).await?;
                if !matches!(response, Reply::Progress { .. }) {
                    bail!("unexpected remote upload response");
                }
                count += n as u64;
                progress(count, size);
            }
            expect_done(channel.request(Request::UploadFinish).await?)?;
            Ok(Outcome::Complete(format!(
                "Uploaded {} bytes securely; SHA-256 verified",
                size,
            )))
        }
        Operation::Download { source, directory } => {
            if !directory.is_dir() { bail!("selected local directory is missing"); }
            send_message_limited(
                &mut channel.output, &Request::Download { path: source.clone() },
                file_service::MAX_PACKET_BYTES,
            ).await?;
            let first: Reply = recv_message_limited(
                &mut channel.input, file_service::MAX_PACKET_BYTES,
            ).await?;
            let (size, expected) = match first {
                Reply::Meta { size, sha256 } => (size, sha256),
                Reply::Failed { reason } => bail!("remote download rejected: {reason}"),
                _ => bail!("invalid file metadata"),
            };
            let filename = Path::new(&source).file_name()
                .context("download path has no filename")?
                .to_string_lossy().to_string();
            let destination = next_download_name(&directory, &filename)?;
            let staging = destination.with_extension(
                format!("xlink-{:016x}.partial", rand::random::<u64>())
            );
            let mut out = OpenOptions::new().write(true).create_new(true).open(&staging)?;
            let mut sha = Sha256::new();
            let mut count = 0u64;
            let transfer = async {
                loop {
                    let message: Reply = recv_message_limited(
                        &mut channel.input, file_service::MAX_PACKET_BYTES
                    ).await?;
                    match message {
                        Reply::Data { bytes } => {
                            if bytes.len() > file_service::BLOCK_BYTES || bytes.is_empty()
                                || count.saturating_add(bytes.len() as u64) > size {
                                bail!("invalid or excessive remote download packet");
                            }
                            out.write_all(&bytes)?;
                            sha.update(&bytes);
                            count += bytes.len() as u64;
                            progress(count, size);
                        }
                        Reply::Done => break,
                        Reply::Failed { reason } => bail!("remote download failed: {reason}"),
                        _ => bail!("unexpected remote download message"),
                    }
                }
                if count != size || sha.finalize().as_slice() != expected {
                    bail!("received file length or SHA-256 mismatched");
                }
                out.sync_all()?;
                Ok::<(),anyhow::Error>(())
            }.await;
            drop(out);
            if let Err(error) = transfer {
                let _ = fs::remove_file(staging);
                return Err(error);
            }
            fs::rename(&staging, &destination)?;
            Ok(Outcome::Complete(format!(
                "Downloaded {} bytes to {}",
                size, destination.display(),
            )))
        }
    }
}

fn expect_done(reply: Reply) -> Result<()> {
    if matches!(reply, Reply::Done) { Ok(()) }
    else { bail!("unexpected file service acknowledgement") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn downloads_refuse_traversal_and_choose_nonconflicting_names() {
        let directory = std::env::temp_dir().join(format!(
            "xlink-download-{}",rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        assert!(next_download_name(&directory,"../bad").is_err());
        let path = next_download_name(&directory,"file.txt").unwrap();
        assert_eq!(path, directory.join("file.txt"));
        fs::write(&path,b"a").unwrap();
        assert_ne!(next_download_name(&directory,"file.txt").unwrap(),path);
        fs::remove_dir_all(directory).unwrap();
    }
}
