//! Low-latency system-audio streaming. Uses the default Windows RENDER
//! endpoint in WASAPI loopback CAPTURE mode; never records a microphone.
//! Each worker owns its own COM apartment, so UI and Tokio threads never
//! share non-Send Windows COM pointers.
use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use wasapi::{get_default_device, initialize_mta, Direction, SampleType, StreamMode, WaveFormat};

pub const SAMPLE_RATE: u32 = 48_000;
pub const CHANNELS: usize = 2;
pub const BYTES_PER_FRAME: usize = CHANNELS * 4; // IEEE-754 f32 stereo
pub const MAX_CHUNK: usize = 32 * 1024; // <= ~85ms per packet
pub const MAX_BUFFER: usize = 96 * 1024; // <= ~250ms jitter/queued data

fn format() -> WaveFormat {
    WaveFormat::new(32, 32, &SampleType::Float, SAMPLE_RATE, CHANNELS, None)
}

/// Capture default speaker output. Bounded channel drops old audio under
/// congestion: stale speech is far worse than a small gap.
pub fn spawn_loopback_capture(
    stop: Arc<AtomicBool>,
) -> Result<mpsc::Receiver<Vec<u8>>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
    thread::Builder::new()
        .name("xlink-wasapi-loopback".into())
        .spawn(move || {
            if let Err(error) = capture_loop(stop, tx) {
                eprintln!("XLINK audio capture ended: {error:#}");
            }
        })
        .context("cannot create Windows audio capture worker")?;
    Ok(rx)
}

fn capture_loop(
    stop: Arc<AtomicBool>, tx: mpsc::SyncSender<Vec<u8>>,
) -> Result<()> {
    initialize_mta().context("WASAPI COM capture initialization failed")?;
    let device = get_default_device(&Direction::Render)
        .context("no default Windows speaker/output to capture")?;
    let mut client = device.get_iaudioclient()?;
    let desired = format();
    let mode = StreamMode::PollingShared {
        autoconvert: true,
        buffer_duration_hns: 300_000, // 30 ms in 100ns units
    };
    // Direction::Capture on render endpoint invokes AUDCLNT_STREAMFLAGS_LOOPBACK.
    client.initialize_client(&desired, &Direction::Capture, &mode)?;
    let capture = client.get_audiocaptureclient()?;
    client.start_stream()?;
    let mut deque = VecDeque::<u8>::new();
    while !stop.load(Ordering::Acquire) {
        capture.read_from_device_to_deque(&mut deque)?;
        // Limit jitter: discard old, already stale sound under CPU/network load.
        if deque.len() > MAX_BUFFER {
            let skip = (deque.len() - MAX_BUFFER) / BYTES_PER_FRAME * BYTES_PER_FRAME;
            deque.drain(..skip);
        }
        while deque.len() >= BYTES_PER_FRAME * 480 { // ten milliseconds
            let desired = deque.len().min(MAX_CHUNK) / BYTES_PER_FRAME * BYTES_PER_FRAME;
            let mut chunk = Vec::with_capacity(desired);
            for _ in 0..desired {
                if let Some(value) = deque.pop_front() { chunk.push(value); }
            }
            if tx.try_send(chunk).is_err() {
                // Drop rather than blocking the audio capture thread.
                break;
            }
        }
        thread::sleep(Duration::from_millis(6));
    }
    let _ = client.stop_stream();
    Ok(())
}

pub fn spawn_playback(
    stop: Arc<AtomicBool>,
) -> Result<mpsc::SyncSender<Vec<u8>>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(6);
    thread::Builder::new().name("xlink-wasapi-speaker".into())
        .spawn(move || {
            if let Err(error) = playback_loop(stop, rx) {
                eprintln!("XLINK audio playback ended: {error:#}");
            }
        }).context("cannot create audio playback worker")?;
    Ok(tx)
}

fn playback_loop(
    stop: Arc<AtomicBool>, rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    initialize_mta().context("WASAPI COM render initialization failed")?;
    let device = get_default_device(&Direction::Render)
        .context("no default audio playback device")?;
    let mut client = device.get_iaudioclient()?;
    let desired = format();
    let mode = StreamMode::PollingShared {
        autoconvert: true, buffer_duration_hns: 300_000,
    };
    client.initialize_client(&desired, &Direction::Render, &mode)?;
    let render = client.get_audiorenderclient()?;
    client.start_stream()?;
    let mut data = VecDeque::<u8>::new();
    while !stop.load(Ordering::Acquire) {
        while let Ok(chunk) = rx.try_recv() {
            validate_chunk(&chunk)?;
            data.extend(chunk);
            if data.len() > MAX_BUFFER {
                let discard = (data.len() - MAX_BUFFER) / BYTES_PER_FRAME * BYTES_PER_FRAME;
                data.drain(..discard);
            }
        }
        let count = client.get_available_space_in_frames()? as usize;
        if count > 0 {
            let writable = count.min(data.len() / BYTES_PER_FRAME);
            if writable > 0 {
                render.write_to_device_from_deque(writable, &mut data, None)?;
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = client.stop_stream();
    Ok(())
}

pub fn validate_chunk(data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > MAX_CHUNK
        || data.len() % BYTES_PER_FRAME != 0 {
        bail!("invalid PCM audio packet size");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audio_packet_limits_are_safe() {
        assert!(validate_chunk(&vec![0u8; BYTES_PER_FRAME * 480]).is_ok());
        assert!(validate_chunk(&vec![0u8; MAX_CHUNK + BYTES_PER_FRAME]).is_err());
        assert!(validate_chunk(&[0u8; 7]).is_err());
    }
}
