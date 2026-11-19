//! Change-driven desktop frames. No network packet is emitted for an unchanged image.
//! Every few seconds a complete keyframe repairs drift and resets delta dependencies.
//! Delta packets use stride==1, with 20 bytes of little-endian metadata:
//! x, y, canvas_width, canvas_height, encoded_patch_stride.
//! Transport remains ordered; decoded patches are always assembled BEFORE
//! any rendered frame is discarded due to viewer backpressure.
use anyhow::{bail, Context, Result};
use nexus_core::FramePacket;
use nexus_display::{CapturedFrame, ViewerFrame};
use std::time::{Duration, Instant};
use crate::frame_codec;

const KEYFRAME_INTERVAL: Duration = Duration::from_secs(5);
const DELTA_HEADER_LEN: usize = 20;
const MAX_CANVAS_BYTES: usize = 64 * 1024 * 1024;

pub struct DeltaEncoder {
    previous: Vec<u8>,
    width: u32,
    height: u32,
    last_keyframe: Option<Instant>,
}

impl DeltaEncoder {
    pub fn new() -> Self {
        Self { previous: Vec::new(), width: 0, height: 0, last_keyframe: None }
    }

    pub fn encode(&mut self, frame: CapturedFrame) -> Result<Option<FramePacket>> {
        let width = frame.width as usize;
        let height = frame.height as usize;
        let expected = width.checked_mul(height).and_then(|n| n.checked_mul(4))
            .context("desktop size overflow")?;
        if expected > MAX_CANVAS_BYTES || frame.stride != frame.width.saturating_mul(4)
            || frame.pixels.len() != expected {
            bail!("invalid desktop buffer for delta encoder");
        }
        let fresh_canvas = self.width != frame.width || self.height != frame.height
            || self.previous.len() != expected;
        let keyframe_due = fresh_canvas || self.last_keyframe.map_or(true,
            |last| last.elapsed() >= KEYFRAME_INTERVAL);

        if keyframe_due {
            let packet = frame_codec::encode(frame.clone())?;
            self.previous = frame.pixels.to_vec();
            self.width = frame.width;
            self.height = frame.height;
            self.last_keyframe = Some(Instant::now());
            return Ok(Some(packet));
        }

        let mut min_x = width;
        let mut min_y = height;
        let mut max_x = 0usize;
        let mut max_y = 0usize;
        let mut changed = false;
        for y in 0..height {
            let start = y * width * 4;
            for x in 0..width {
                let index = start + x * 4;
                if self.previous[index..index + 4] != frame.pixels[index..index + 4] {
                    changed = true;
                    min_x = min_x.min(x);
                    min_y = min_y.min(y);
                    max_x = max_x.max(x);
                    max_y = max_y.max(y);
                }
            }
        }
        if !changed {
            return Ok(None);
        }

        // A broad dirty region is more efficient as one full JPEG frame.
        let patch_width = max_x - min_x + 1;
        let patch_height = max_y - min_y + 1;
        let patch_area = patch_width * patch_height;
        let full_area = width * height;
        let packet = if patch_area * 2 >= full_area {
            frame_codec::encode(frame.clone())?
        } else {
            let mut patch_pixels = Vec::with_capacity(patch_area * 4);
            for y in min_y..=max_y {
                let start = (y * width + min_x) * 4;
                patch_pixels.extend_from_slice(&frame.pixels[start..start + patch_width * 4]);
            }
            let patch = CapturedFrame {
                width: patch_width as u32,
                height: patch_height as u32,
                stride: (patch_width * 4) as u32,
                frame_index: frame.frame_index,
                pixels: patch_pixels.into(),
            };
            let encoded = frame_codec::encode(patch)?;
            let mut payload = Vec::with_capacity(DELTA_HEADER_LEN + encoded.pixels.len());
            for value in [
                min_x as u32,
                min_y as u32,
                frame.width,
                frame.height,
                encoded.stride,
            ] {
                payload.extend_from_slice(&value.to_le_bytes());
            }
            payload.extend_from_slice(&encoded.pixels);
            FramePacket {
                sequence: frame.frame_index,
                width: encoded.width,
                height: encoded.height,
                stride: 1, // patch marker: not BGRA and not a complete JPEG frame
                pixels: payload,
            }
        };

        // Update only after a valid packet has been encoded. QUIC delivery is
        // ordered and reliable; send errors terminate the session.
        self.previous.copy_from_slice(&frame.pixels);
        Ok(Some(packet))
    }
}

pub struct DeltaDecoder {
    canvas: Option<ViewerFrame>,
    last_sequence: Option<u64>,
}

impl DeltaDecoder {
    pub fn new() -> Self {
        Self { canvas: None, last_sequence: None }
    }

    pub fn decode(&mut self, packet: FramePacket) -> Result<ViewerFrame> {
        if let Some(previous) = self.last_sequence {
            if packet.sequence <= previous {
                bail!("out-of-order or replayed desktop frame");
            }
        }
        let sequence = packet.sequence;
        if packet.stride != 1 {
            let frame = frame_codec::decode(packet)?;
            self.canvas = Some(frame.clone());
            self.last_sequence = Some(sequence);
            return Ok(frame);
        }

        if packet.pixels.len() < DELTA_HEADER_LEN {
            bail!("truncated delta packet");
        }
        let read = |offset: usize| u32::from_le_bytes(
            packet.pixels[offset..offset + 4].try_into().expect("fixed delta header"));
        let x = read(0) as usize;
        let y = read(4) as usize;
        let canvas_width = read(8);
        let canvas_height = read(12);
        let patch_stride = read(16);
        let canvas = self.canvas.as_mut().context("delta arrived without a full keyframe")?;
        if canvas.width != canvas_width || canvas.height != canvas_height {
            bail!("delta canvas dimensions mismatch");
        }
        let right = x.checked_add(packet.width as usize).context("delta x overflow")?;
        let bottom = y.checked_add(packet.height as usize).context("delta y overflow")?;
        if right > canvas.width as usize || bottom > canvas.height as usize {
            bail!("delta rectangle exceeds canvas");
        }
        if patch_stride == 1 {
            bail!("nested delta packets are invalid");
        }
        let patch = frame_codec::decode(FramePacket {
            sequence, width: packet.width, height: packet.height,
            stride: patch_stride, pixels: packet.pixels[DELTA_HEADER_LEN..].to_vec(),
        })?;
        for row in 0..packet.height as usize {
            let dst = ((y + row) * canvas.width as usize + x) * 4;
            let src = row * patch.stride as usize;
            let bytes = packet.width as usize * 4;
            canvas.pixels[dst..dst + bytes].copy_from_slice(&patch.pixels[src..src + bytes]);
        }
        self.last_sequence = Some(sequence);
        Ok(canvas.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capture(width: u32, height: u32, n: u64, pixels: Vec<u8>) -> CapturedFrame {
        CapturedFrame { width, height, stride: width * 4, frame_index: n, pixels: pixels.into() }
    }

    #[test]
    fn unchanged_screen_emits_nothing() {
        let mut encoder = DeltaEncoder::new();
        let pixels = vec![0u8; 64 * 64 * 4];
        assert!(encoder.encode(capture(64, 64, 0, pixels.clone())).unwrap().is_some());
        assert!(encoder.encode(capture(64, 64, 1, pixels)).unwrap().is_none());
    }

    #[test]
    fn small_dirty_rectangle_preserves_canvas() {
        let mut encoder = DeltaEncoder::new();
        let mut decoder = DeltaDecoder::new();
        let blank = vec![0u8; 64 * 64 * 4];
        let full = encoder.encode(capture(64, 64, 0, blank.clone())).unwrap().unwrap();
        decoder.decode(full).unwrap();
        let mut changed = blank;
        for y in 10..14 {
            for x in 9..13 {
                let start = (y * 64 + x) * 4;
                changed[start..start + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
        let patch = encoder.encode(capture(64, 64, 1, changed)).unwrap().unwrap();
        assert_eq!(patch.stride, 1);
        let output = decoder.decode(patch).unwrap();
        assert_eq!(&output.pixels[(11 * 64 + 11)*4..(11 * 64 + 11)*4+3], &[255,255,255]);
        assert_eq!(&output.pixels[0..3], &[0,0,0]);
    }

    #[test]
    fn delta_without_full_keyframe_fails_closed() {
        let mut encoder = DeltaEncoder::new();
        let blank = vec![0u8; 64*64*4];
        encoder.encode(capture(64, 64, 0, blank.clone())).unwrap();
        let mut changed = blank;
        changed[0..4].copy_from_slice(&[255,255,255,255]);
        let patch = encoder.encode(capture(64, 64, 1, changed)).unwrap().unwrap();
        assert!(DeltaDecoder::new().decode(patch).is_err());
    }

    #[test]
    fn dimension_change_emits_full_keyframe() {
        let mut encoder = DeltaEncoder::new();
        encoder.encode(capture(8, 8, 0, vec![0u8; 8*8*4])).unwrap();
        let changed = encoder.encode(capture(10, 10, 1, vec![0u8; 10*10*4])).unwrap().unwrap();
        assert_ne!(changed.stride, 1);
    }
}
