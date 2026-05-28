use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use minifb::{Key, KeyRepeat, MouseMode, Window, WindowOptions};
use std::thread;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub frame_index: u64,
    pub pixels: Bytes,
}

#[derive(Debug)]
pub struct ScreenCapturer {
    width: u32,
    height: u32,
    stride: u32,
    frame_index: u64,
}

#[derive(Debug, Clone)]
pub struct ViewerFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixels: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ViewerInputEvent {
    MouseMove { x_norm: f32, y_norm: f32 },
    Keyboard { virtual_key: u16, pressed: bool },
}

impl ScreenCapturer {
    pub fn new() -> Result<Self> {
        let (width, height) = desktop_dimensions().unwrap_or((1280, 720));
        let stride = width
            .checked_mul(4)
            .ok_or_else(|| anyhow!("frame stride overflow"))?;

        Ok(Self {
            width,
            height,
            stride,
            frame_index: 0,
        })
    }

    pub fn capture_frame(&mut self) -> Result<CapturedFrame> {
        let buffer_len = (self.stride as usize)
            .checked_mul(self.height as usize)
            .ok_or_else(|| anyhow!("frame buffer overflow"))?;
        let mut pixels = vec![0_u8; buffer_len];
        let phase = (self.frame_index % 255) as u8;

        for y in 0..self.height {
            for x in 0..self.width {
                let offset = (y * self.stride + x * 4) as usize;
                pixels[offset] = ((x as u64 + self.frame_index) % 255) as u8;
                pixels[offset + 1] = ((y as u64 + (self.frame_index * 2)) % 255) as u8;
                pixels[offset + 2] = phase;
                pixels[offset + 3] = 255;
            }
        }

        let marker_x = (self.frame_index as u32 * 13) % self.width.max(1);
        for y in 0..self.height.min(48) {
            let offset = (y * self.stride + marker_x * 4) as usize;
            pixels[offset] = 0;
            pixels[offset + 1] = 255;
            pixels[offset + 2] = 255;
            pixels[offset + 3] = 255;
        }

        let frame = CapturedFrame {
            width: self.width,
            height: self.height,
            stride: self.stride,
            frame_index: self.frame_index,
            pixels: Bytes::from(pixels),
        };
        self.frame_index += 1;
        Ok(frame)
    }
}

pub fn spawn_remote_viewer(
    title: &str,
) -> Result<(UnboundedSender<ViewerFrame>, UnboundedReceiver<ViewerInputEvent>)> {
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<ViewerFrame>();
    let (input_tx, input_rx) = mpsc::unbounded_channel::<ViewerInputEvent>();
    let title = title.to_string();

    thread::Builder::new()
        .name("nexus-remote-viewer".to_string())
        .spawn(move || {
            if let Err(error) = run_remote_viewer(&title, &mut frame_rx, input_tx) {
                eprintln!("remote viewer exited with error: {error:#}");
            }
        })
        .context("failed to spawn remote viewer thread")?;

    Ok((frame_tx, input_rx))
}

fn run_remote_viewer(
    title: &str,
    frame_rx: &mut UnboundedReceiver<ViewerFrame>,
    input_tx: UnboundedSender<ViewerInputEvent>,
) -> Result<()> {
    let Some(mut latest_frame) = frame_rx.blocking_recv() else {
        return Ok(());
    };

    let mut width = latest_frame.width.max(1) as usize;
    let mut height = latest_frame.height.max(1) as usize;
    let mut window = Window::new(title, width, height, WindowOptions::default())
        .map_err(|error| anyhow!("failed to create remote viewer window: {error}"))?;
    window.set_target_fps(60);

    let mut pixel_buffer = vec![0_u32; width * height];
    let mut last_mouse_absolute: Option<(u16, u16)> = None;

    loop {
        if !window.is_open() {
            break;
        }

        while let Ok(frame) = frame_rx.try_recv() {
            latest_frame = frame;
        }

        if latest_frame.width as usize != width || latest_frame.height as usize != height {
            width = latest_frame.width.max(1) as usize;
            height = latest_frame.height.max(1) as usize;
            pixel_buffer.resize(width * height, 0_u32);
            window = Window::new(title, width, height, WindowOptions::default())
                .map_err(|error| anyhow!("failed to rebuild remote viewer window: {error}"))?;
            window.set_target_fps(60);
            last_mouse_absolute = None;
        }

        copy_bgra_into_u32(&latest_frame, &mut pixel_buffer)?;
        capture_window_input(&window, width, height, &input_tx, &mut last_mouse_absolute);

        window
            .update_with_buffer(&pixel_buffer, width, height)
            .map_err(|error| anyhow!("failed to present frame: {error}"))?;
    }

    Ok(())
}

fn copy_bgra_into_u32(frame: &ViewerFrame, output: &mut [u32]) -> Result<()> {
    let width = frame.width as usize;
    let height = frame.height as usize;
    let stride = frame.stride as usize;
    let required = stride
        .checked_mul(height)
        .ok_or_else(|| anyhow!("frame stride overflow during conversion"))?;

    if frame.pixels.len() < required {
        return Err(anyhow!(
            "invalid frame payload size: got {}, need at least {}",
            frame.pixels.len(),
            required
        ));
    }

    let output_required = width
        .checked_mul(height)
        .ok_or_else(|| anyhow!("window buffer overflow during conversion"))?;
    if output.len() < output_required {
        return Err(anyhow!(
            "invalid output buffer size: got {}, need at least {}",
            output.len(),
            output_required
        ));
    }

    for y in 0..height {
        for x in 0..width {
            let source_index = y * stride + x * 4;
            let blue = frame.pixels[source_index] as u32;
            let green = frame.pixels[source_index + 1] as u32;
            let red = frame.pixels[source_index + 2] as u32;
            output[y * width + x] = 0xFF00_0000 | (red << 16) | (green << 8) | blue;
        }
    }

    Ok(())
}

fn capture_window_input(
    window: &Window,
    width: usize,
    height: usize,
    input_tx: &UnboundedSender<ViewerInputEvent>,
    last_mouse_absolute: &mut Option<(u16, u16)>,
) {
    if let Some((mouse_x, mouse_y)) = window.get_mouse_pos(MouseMode::Discard) {
        let x_norm = normalize_position(mouse_x, width);
        let y_norm = normalize_position(mouse_y, height);
        let absolute = (
            (x_norm * u16::MAX as f32).round() as u16,
            (y_norm * u16::MAX as f32).round() as u16,
        );

        if Some(absolute) != *last_mouse_absolute {
            let _ = input_tx.send(ViewerInputEvent::MouseMove { x_norm, y_norm });
            *last_mouse_absolute = Some(absolute);
        }
    }

    for key in window.get_keys_pressed(KeyRepeat::No) {
        if let Some(virtual_key) = minifb_key_to_virtual_key(key) {
            let _ = input_tx.send(ViewerInputEvent::Keyboard {
                virtual_key,
                pressed: true,
            });
        }
    }

    for key in window.get_keys_released() {
        if let Some(virtual_key) = minifb_key_to_virtual_key(key) {
            let _ = input_tx.send(ViewerInputEvent::Keyboard {
                virtual_key,
                pressed: false,
            });
        }
    }
}

fn normalize_position(value: f32, max_extent: usize) -> f32 {
    if max_extent <= 1 {
        return 0.0;
    }

    let denominator = (max_extent - 1) as f32;
    (value / denominator).clamp(0.0, 1.0)
}

fn minifb_key_to_virtual_key(key: Key) -> Option<u16> {
    match key {
        Key::A => Some(0x41),
        Key::B => Some(0x42),
        Key::C => Some(0x43),
        Key::D => Some(0x44),
        Key::E => Some(0x45),
        Key::F => Some(0x46),
        Key::G => Some(0x47),
        Key::H => Some(0x48),
        Key::I => Some(0x49),
        Key::J => Some(0x4A),
        Key::K => Some(0x4B),
        Key::L => Some(0x4C),
        Key::M => Some(0x4D),
        Key::N => Some(0x4E),
        Key::O => Some(0x4F),
        Key::P => Some(0x50),
        Key::Q => Some(0x51),
        Key::R => Some(0x52),
        Key::S => Some(0x53),
        Key::T => Some(0x54),
        Key::U => Some(0x55),
        Key::V => Some(0x56),
        Key::W => Some(0x57),
        Key::X => Some(0x58),
        Key::Y => Some(0x59),
        Key::Z => Some(0x5A),
        Key::Key0 => Some(0x30),
        Key::Key1 => Some(0x31),
        Key::Key2 => Some(0x32),
        Key::Key3 => Some(0x33),
        Key::Key4 => Some(0x34),
        Key::Key5 => Some(0x35),
        Key::Key6 => Some(0x36),
        Key::Key7 => Some(0x37),
        Key::Key8 => Some(0x38),
        Key::Key9 => Some(0x39),
        Key::Enter => Some(0x0D),
        Key::Escape => Some(0x1B),
        Key::Backspace => Some(0x08),
        Key::Tab => Some(0x09),
        Key::Space => Some(0x20),
        Key::Left => Some(0x25),
        Key::Up => Some(0x26),
        Key::Right => Some(0x27),
        Key::Down => Some(0x28),
        Key::LeftShift | Key::RightShift => Some(0x10),
        Key::LeftCtrl | Key::RightCtrl => Some(0x11),
        Key::LeftAlt | Key::RightAlt => Some(0x12),
        _ => None,
    }
}

fn desktop_dimensions() -> Option<(u32, u32)> {
    unsafe {
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width > 0 && height > 0 {
            Some((width as u32, height as u32))
        } else {
            None
        }
    }
}