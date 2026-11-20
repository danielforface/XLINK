//! One-shot screenshots to Downloads AND the Windows image clipboard.
//! Both remote and local capture use BGRA->RGBA conversion and bounded sizes.
use anyhow::{bail, Context, Result};
use arboard::{Clipboard, ImageData};
use nexus_display::{CapturedFrame, ScreenCapturer, ViewerFrame};
use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

fn rgba_from_bgra(
    pixels: &[u8], width: u32, height: u32, stride: u32,
) -> Result<Vec<u8>> {
    let count = (width as usize).checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4)).context("image dimensions overflow")?;
    let row_bytes = (width as usize).checked_mul(4).context("invalid image stride")?;
    if count == 0 || count > MAX_CAPTURE_BYTES || (stride as usize) < row_bytes
        || pixels.len() < (stride as usize).checked_mul(height as usize)
            .context("frame byte size overflow")? {
        bail!("invalid frame dimensions for screenshot");
    }
    let mut rgba = vec![0u8; count];
    for y in 0..height as usize {
        let src = &pixels[y * stride as usize..y * stride as usize + row_bytes];
        let dst = &mut rgba[y * row_bytes..(y + 1) * row_bytes];
        for (from, to) in src.chunks_exact(4).zip(dst.chunks_exact_mut(4)) {
            to.copy_from_slice(&[from[2], from[1], from[0], 255]);
        }
    }
    Ok(rgba)
}

fn downloads_folder() -> Result<PathBuf> {
    // Well-known default user Downloads; no privileges or remote folder needed.
    // Redirection-aware Windows KnownFolder support can be added separately.
    let home = std::env::var_os("USERPROFILE")
        .context("cannot locate current Windows user profile")?;
    let folder = PathBuf::from(home).join("Downloads");
    fs::create_dir_all(&folder).context("cannot access Downloads folder")?;
    Ok(folder)
}

fn write_and_copy(width: u32, height: u32, rgba: Vec<u8>, side: &str)
    -> Result<PathBuf>
{
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    let directory = downloads_folder()?;
    let mut result = None;
    for number in 0..100u32 {
        let path = directory.join(format!(
            "XLINK-{}-{}-{:09}-{}.png", side,
            now.as_secs(), now.subsec_nanos(), number,
        ));
        let file = fs::OpenOptions::new().write(true).create_new(true).open(&path);
        match file {
            Ok(file) => {
                let encoder = image::codecs::png::PngEncoder::new(file);
                use image::ImageEncoder as _;
                encoder.write_image(
                    &rgba, width, height, image::ExtendedColorType::Rgba8,
                ).context("failed to encode PNG screenshot")?;
                result = Some(path);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("cannot create Downloads screenshot"),
        }
    }
    let path = result.context("unable to allocate unique screenshot name")?;
    let mut clipboard = Clipboard::new().context("Windows image clipboard unavailable")?;
    clipboard.set_image(ImageData {
        width: width as usize,
        height: height as usize,
        bytes: Cow::Owned(rgba),
    }).context("cannot place screenshot on clipboard")?;
    Ok(path)
}

pub fn capture_remote(frame: ViewerFrame) -> Result<PathBuf> {
    let rgba = rgba_from_bgra(&frame.pixels, frame.width, frame.height, frame.stride)?;
    write_and_copy(frame.width, frame.height, rgba, "remote")
}

pub fn capture_local() -> Result<PathBuf> {
    let mut capturer = ScreenCapturer::new()?;
    let frame: CapturedFrame = capturer.capture_frame()?;
    let rgba = rgba_from_bgra(&frame.pixels, frame.width, frame.height, frame.stride)?;
    write_and_copy(frame.width, frame.height, rgba, "local")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversion_preserves_colors_and_checks_bounds() {
        let pixels = [10, 20, 30, 255, 40, 50, 60, 255];
        let output = rgba_from_bgra(&pixels, 2, 1, 8).unwrap();
        assert_eq!(output, vec![30, 20, 10, 255, 60, 50, 40, 255]);
        assert!(rgba_from_bgra(&pixels, 3, 1, 8).is_err());
        assert!(rgba_from_bgra(&pixels, u32::MAX, u32::MAX, 0).is_err());
    }
}
