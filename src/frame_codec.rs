//! Bounded remote desktop wire-frame codec.
//! stride == 0 is JPEG; stride >= width * 4 is uncompressed BGRA.
//! Bump protocol version when changing these wire semantics.
use anyhow::{anyhow, bail, Context, Result};
use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageFormat, ImageReader, Limits};
use nexus_core::FramePacket;
use nexus_display::{CapturedFrame, ViewerFrame};
use std::io::Cursor;

pub const MAX_DIMENSION: u32 = 8192;
pub const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
const JPEG_QUALITY: u8 = 70;

fn dimensions_valid(width: u32, height: u32) -> Result<usize> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        bail!("invalid frame dimensions {width}x{height}");
    }
    let bytes = (width as usize)
        .checked_mul(height as usize)
        .and_then(|x| x.checked_mul(4))
        .ok_or_else(|| anyhow!("frame size overflow"))?;
    if bytes > MAX_DECODED_BYTES {
        bail!("frame exceeds decoded allocation limit");
    }
    Ok(bytes)
}

/// Bound the number of pixels transmitted before JPEG compression.
/// Keep aspect ratio to preserve normalized pointer coordinates.
/// Triangle filtering keeps desktop text more legible than nearest-neighbor.
pub fn fit_desktop(frame: CapturedFrame, max_width: u32, max_height: u32) -> Result<CapturedFrame> {
    let _ = dimensions_valid(frame.width, frame.height)?;
    if frame.stride != frame.width.saturating_mul(4)
        || frame.pixels.len() != frame.width as usize * frame.height as usize * 4 {
        bail!("invalid BGRA source for resizing");
    }
    if max_width == 0 || max_height == 0 {
        bail!("invalid resize ceiling");
    }
    if frame.width <= max_width && frame.height <= max_height {
        return Ok(frame);
    }
    let scale = (max_width as f64 / frame.width as f64)
        .min(max_height as f64 / frame.height as f64);
    let dst_width = ((frame.width as f64 * scale).floor() as u32).max(1);
    let dst_height = ((frame.height as f64 * scale).floor() as u32).max(1);
    let original = image::RgbaImage::from_raw(
        frame.width, frame.height, frame.pixels.to_vec(),
    ).context("unable to interpret BGRA desktop buffer as four channels")?;
    // Channel order remains BGRA throughout; the resampler is channel-agnostic.
    let resized = image::imageops::resize(
        &original, dst_width, dst_height, image::imageops::FilterType::Triangle,
    );
    Ok(CapturedFrame {
        width: dst_width,
        height: dst_height,
        stride: dst_width * 4,
        frame_index: frame.frame_index,
        pixels: resized.into_raw().into(),
    })
}

pub fn encode(frame: CapturedFrame) -> Result<FramePacket> {
    let required = dimensions_valid(frame.width, frame.height)?;
    if frame.stride != frame.width * 4 || frame.pixels.len() != required {
        bail!("invalid captured BGRA frame");
    }

    let mut rgb = Vec::with_capacity(required / 4 * 3);
    for px in frame.pixels.chunks_exact(4) {
        rgb.extend_from_slice(&[px[2], px[1], px[0]]);
    }

    let mut encoded = Vec::new();
    let jpeg_result = JpegEncoder::new_with_quality(&mut encoded, JPEG_QUALITY)
        .encode(&rgb, frame.width, frame.height, ExtendedColorType::Rgb8);

    // Poorly-compressible images must retain an interoperable raw fallback.
    let (stride, pixels) = match jpeg_result {
        Ok(()) if encoded.len() < frame.pixels.len() => (0, encoded),
        _ => (frame.stride, frame.pixels.to_vec()),
    };
    Ok(FramePacket {
        sequence: frame.frame_index,
        width: frame.width,
        height: frame.height,
        stride,
        pixels,
    })
}

pub fn decode(packet: FramePacket) -> Result<ViewerFrame> {
    let required = dimensions_valid(packet.width, packet.height)?;
    if packet.stride == 0 {
        if packet.pixels.is_empty() || packet.pixels.len() > MAX_DECODED_BYTES {
            bail!("invalid JPEG payload size");
        }
        let mut reader = ImageReader::with_format(Cursor::new(&packet.pixels), ImageFormat::Jpeg);
        let mut limits = Limits::default();
        limits.max_image_width = Some(MAX_DIMENSION);
        limits.max_image_height = Some(MAX_DIMENSION);
        limits.max_alloc = Some(MAX_DECODED_BYTES as u64);
        reader.limits(limits);
        let image = reader.decode().context("failed to decode JPEG frame")?;
        if image.width() != packet.width || image.height() != packet.height {
            bail!("JPEG dimensions differ from transport metadata");
        }
        let rgb = image.to_rgb8();
        let mut bgra = Vec::with_capacity(required);
        for px in rgb.as_raw().chunks_exact(3) {
            bgra.extend_from_slice(&[px[2], px[1], px[0], 255]);
        }
        return Ok(ViewerFrame {
            width: packet.width, height: packet.height, stride: packet.width * 4, pixels: bgra,
        });
    }

    if packet.stride != packet.width * 4 || packet.pixels.len() != required {
        bail!("invalid uncompressed BGRA payload");
    }
    Ok(ViewerFrame {
        width: packet.width, height: packet.height, stride: packet.stride, pixels: packet.pixels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(width: u32, height: u32) -> CapturedFrame {
        let mut pixels = Vec::new();
        for _ in 0..(width * height) {
            pixels.extend_from_slice(&[22, 60, 180, 255]);
        }
        CapturedFrame {
            width, height, stride: width * 4, frame_index: 7, pixels: pixels.into(),
        }
    }

    #[test]
    fn fit_desktop_preserves_aspect_and_small_originals() {
        let small = captured(64, 64);
        assert_eq!(fit_desktop(small, 1280, 800).unwrap().width, 64);
        let large = captured(1920, 1080);
        let reduced = fit_desktop(large, 1280, 800).unwrap();
        assert_eq!((reduced.width, reduced.height), (1280, 720));
        assert_eq!(reduced.pixels.len(), 1280 * 720 * 4);
    }

    #[test]
    fn jpeg_roundtrip_preserves_size_and_rough_colors() {
        let packet = encode(captured(64, 64)).unwrap();
        assert_eq!(packet.stride, 0, "uniform frame should compress");
        let viewer = decode(packet).unwrap();
        assert_eq!(viewer.pixels.len(), 64 * 64 * 4);
        assert!((viewer.pixels[0] as i16 - 22).abs() < 12);
        assert!((viewer.pixels[2] as i16 - 180).abs() < 12);
    }

    #[test]
    fn rejects_corrupted_jpeg_and_dimensions() {
        let mut packet = encode(captured(16, 16)).unwrap();
        packet.pixels = vec![1, 2, 3, 4];
        assert!(decode(packet).is_err());
        let mut packet = encode(captured(16, 16)).unwrap();
        packet.width = 17;
        assert!(decode(packet).is_err());
    }

    #[test]
    fn valid_raw_frame_remains_compatible() {
        let packet = FramePacket {
            sequence: 1, width: 1, height: 1, stride: 4, pixels: vec![1, 2, 3, 255],
        };
        assert_eq!(decode(packet).unwrap().pixels, vec![1, 2, 3, 255]);
    }

    #[test]
    fn rejects_oversized_or_invalid_stride() {
        assert!(dimensions_valid(8192, 8192).is_err());
        let packet = FramePacket {
            sequence: 0, width: 100, height: 100, stride: 1, pixels: vec![0; 100],
        };
        assert!(decode(packet).is_err());
    }
}
