//! Human-initiated action recording and bounded, cancelable timed playback.
//! Records ONLY XLINK viewer-dispatched actions, never global keyboard hooks,
//! passwords outside XLINK, video, files or audio. Transferrable .xlaction
//! files are intentionally portable and should be handled as sensitive.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 8] = b"XLINKACT";
const FORMAT: u16 = 1;
const MAX_EVENT_BYTES: usize = 96;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Move { x_norm: f32, y_norm: f32 },
    Button { button: u8, pressed: bool },
    Key { virtual_key: u16, pressed: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimedAction {
    pub at_ms: u64,
    pub action: Action,
}

fn validate(action: &TimedAction) -> Result<()> {
    match action.action {
        Action::Move { x_norm, y_norm }
            if !x_norm.is_finite() || !y_norm.is_finite()
                || !(0.0..=1.0).contains(&x_norm)
                || !(0.0..=1.0).contains(&y_norm) => bail!("invalid mouse position"),
        Action::Button { button, .. } if button > 2 => bail!("invalid mouse button"),
        Action::Key { virtual_key, .. } if virtual_key == 0 || virtual_key > 0xFF =>
            bail!("invalid virtual key"),
        _ => Ok(()),
    }
}

fn downloads() -> Result<PathBuf> {
    let profile = std::env::var_os("USERPROFILE")
        .context("Windows user profile not available")?;
    let folder = PathBuf::from(profile).join("Downloads");
    fs::create_dir_all(&folder)?;
    Ok(folder)
}

pub struct Recorder {
    file: BufWriter<File>,
    began: Instant,
    path: PathBuf,
    last_ms: u64,
    count: u64,
}
impl Recorder {
    pub fn start() -> Result<Self> {
        let directory = downloads()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        for nonce in 0..100u32 {
            let path = directory.join(format!("XLINK-Action-{now}-{nonce}.xlaction"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(MAGIC)?;
                    file.write_all(&FORMAT.to_le_bytes())?;
                    return Ok(Self {
                        file: BufWriter::new(file), began: Instant::now(),
                        path, last_ms: 0, count: 0,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e).context("cannot create recording in Downloads"),
            }
        }
        bail!("cannot allocate unique action recording")
    }

    pub fn push(&mut self, action: Action) -> Result<()> {
        let item = TimedAction {
            at_ms: self.began.elapsed().as_millis().min(u64::MAX as u128) as u64,
            action,
        };
        validate(&item)?;
        if item.at_ms < self.last_ms {
            bail!("non-monotonic event clock");
        }
        let bytes = bincode::serialize(&item)?;
        if bytes.len() > MAX_EVENT_BYTES { bail!("oversized action packet"); }
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.last_ms = item.at_ms;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(PathBuf, u64)> {
        self.file.flush()?;
        self.file.get_ref().sync_all()?;
        Ok((self.path, self.count))
    }
}
struct Reader {
    file: BufReader<File>,
    last_ms: u64,
}
impl Reader {
    fn open(path: &Path) -> Result<Self> {
        let mut file = BufReader::new(File::open(path)
            .context("cannot open selected action recording")?);
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != MAGIC { bail!("not an XLINK action file"); }
        let mut version = [0u8; 2];
        file.read_exact(&mut version)?;
        if u16::from_le_bytes(version) != FORMAT { bail!("unsupported action file version"); }
        Ok(Self { file, last_ms: 0 })
    }

    fn next(&mut self) -> Result<Option<TimedAction>> {
        let mut raw_len = [0u8; 4];
        if self.file.read(&mut raw_len[..1])? == 0 { return Ok(None); }
        self.file.read_exact(&mut raw_len[1..])?;
        let len = u32::from_le_bytes(raw_len) as usize;
        if len == 0 || len > MAX_EVENT_BYTES { bail!("invalid action record length"); }
        let mut bytes = vec![0u8; len];
        self.file.read_exact(&mut bytes)?;
        let event: TimedAction = bincode::deserialize(&bytes)?;
        validate(&event)?;
        if event.at_ms < self.last_ms { bail!("action timestamps must be increasing"); }
        self.last_ms = event.at_ms;
        Ok(Some(event))
    }
}

pub fn inspect(path: &Path) -> Result<(u64, u64)> {
    let mut reader = Reader::open(path)?;
    let mut count = 0u64;
    let mut duration = 0u64;
    while let Some(event) = reader.next()? {
        count += 1;
        duration = event.at_ms;
    }
    Ok((count, duration))
}

/// Replay events at their exact relative timestamps. A caller owns the
/// cancellation token; even infinite replay can be stopped at any moment.
/// This function never manipulates OS input on its own: only the explicitly
/// authorized session callback sends the event.
pub async fn replay<F, Fut>(
    path: &Path, repeats: Option<u32>, stop: &AtomicBool, mut emit: F,
) -> Result<u64>
where
    F: FnMut(Action) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if repeats == Some(0) { bail!("repeat count must be positive"); }
    let mut executed = 0u64;
    let mut rounds = 0u64;
    loop {
        if stop.load(Ordering::Acquire) { break; }
        if repeats.map_or(false, |limit| rounds >= u64::from(limit)) { break; }
        let mut reader = Reader::open(path)?;
        let origin = tokio::time::Instant::now();
        while let Some(event) = reader.next()? {
            if stop.load(Ordering::Acquire) { break; }
            tokio::time::sleep_until(
                origin + Duration::from_millis(event.at_ms)
            ).await;
            if stop.load(Ordering::Acquire) { break; }
            emit(event.action).await?;
            executed += 1;
        }
        rounds += 1;
    }
    Ok(executed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_action_file_is_rejected_without_execution() {
        let path = std::env::temp_dir().join(format!(
            "xlink-action-invalid-{}.xlaction", rand::random::<u64>()
        ));
        fs::write(&path, b"notanxlinkfile").unwrap();
        assert!(inspect(&path).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn event_validation_is_strict() {
        let event = TimedAction {
            at_ms: 5, action: Action::Move {x_norm: f32::NAN, y_norm: 0.5}
        };
        assert!(validate(&event).is_err());
        let event = TimedAction {
            at_ms: 7, action: Action::Button {button: 3, pressed: true}
        };
        assert!(validate(&event).is_err());
    }
}
