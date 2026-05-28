use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use minifb::{Key, KeyRepeat, MouseMode, Window, WindowOptions};
use std::thread;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use windows::core::{ComInterface, Error as WindowsError};
use windows::Win32::Foundation::E_FAIL;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    Common::DXGI_FORMAT_B8G8R8A8_UNORM, IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO,
};
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
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging_texture: Option<ID3D11Texture2D>,
    width: u32,
    height: u32,
    stride: u32,
    frame_index: u64,
    last_pixels: Option<Bytes>,
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
        let (device, context) = create_d3d11_device()?;
        let duplication = create_output_duplication(&device)?;
        let (width, height) = desktop_dimensions().unwrap_or((1280, 720));
        let stride = width
            .checked_mul(4)
            .ok_or_else(|| anyhow!("frame stride overflow"))?;

        Ok(Self {
            device,
            context,
            duplication,
            staging_texture: None,
            width,
            height,
            stride,
            frame_index: 0,
            last_pixels: None,
        })
    }

    pub fn capture_frame(&mut self) -> Result<CapturedFrame> {
        for _ in 0..3 {
            match self.try_capture_frame() {
                Ok(frame) => return Ok(frame),
                Err(error) if error.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                    continue;
                }
                Err(error) if error.code() == DXGI_ERROR_ACCESS_LOST => {
                    self.duplication = create_output_duplication(&self.device)
                        .context("failed to recreate duplication after access loss")?;
                    self.staging_texture = None;
                    continue;
                }
                Err(error) => {
                    return Err(anyhow!(
                        "AcquireNextFrame/desktop copy failed: {} ({:?})",
                        error.message(),
                        error.code()
                    ));
                }
            }
        }

        let pixels = self
            .last_pixels
            .clone()
            .ok_or_else(|| anyhow!("timed out waiting for desktop frame"))?;

        let frame = CapturedFrame {
            width: self.width,
            height: self.height,
            stride: self.stride,
            frame_index: self.frame_index,
            pixels,
        };
        self.frame_index += 1;
        Ok(frame)
    }

    fn try_capture_frame(&mut self) -> std::result::Result<CapturedFrame, WindowsError> {
        unsafe {
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource = None;

            self.duplication
                .AcquireNextFrame(16, &mut frame_info, &mut resource)?;

            let _release_guard = FrameReleaseGuard::new(self.duplication.clone());
            let resource = resource.ok_or_else(|| {
                WindowsError::new(
                    E_FAIL.into(),
                    "AcquireNextFrame returned no resource".into(),
                )
            })?;

            let desktop_texture: ID3D11Texture2D = resource.cast()?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            desktop_texture.GetDesc(&mut desc);

            if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
                return Err(WindowsError::new(
                    E_FAIL.into(),
                    "unexpected desktop duplication format".into(),
                ));
            }

            let staging = self.ensure_staging_texture(desc)?;

            let staging_resource: ID3D11Resource = staging.cast()?;
            let desktop_resource: ID3D11Resource = desktop_texture.cast()?;

            self.context.CopyResource(&staging_resource, &desktop_resource);

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging_resource, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
            let _unmap_guard = MapUnmapGuard::new(self.context.clone(), staging_resource.clone());

            let width = desc.Width as usize;
            let height = desc.Height as usize;
            let dst_stride = width * 4;
            let src_stride = mapped.RowPitch as usize;

            let mut pixels = vec![0_u8; dst_stride * height];
            let base_ptr = mapped.pData as *const u8;

            for row in 0..height {
                let src_row = std::slice::from_raw_parts(base_ptr.add(src_stride * row), dst_stride);
                let dst_start = row * dst_stride;
                let dst_end = dst_start + dst_stride;
                pixels[dst_start..dst_end].copy_from_slice(src_row);
            }

            self.width = desc.Width;
            self.height = desc.Height;
            self.stride = dst_stride as u32;

            let pixels = Bytes::from(pixels);
            self.last_pixels = Some(pixels.clone());

            let frame = CapturedFrame {
                width: self.width,
                height: self.height,
                stride: self.stride,
                frame_index: self.frame_index,
                pixels,
            };
            self.frame_index += 1;
            Ok(frame)
        }
    }

    fn ensure_staging_texture(
        &mut self,
        mut source_desc: D3D11_TEXTURE2D_DESC,
    ) -> std::result::Result<ID3D11Texture2D, WindowsError> {
        let needs_recreate = match &self.staging_texture {
            Some(existing) => {
                let mut existing_desc = D3D11_TEXTURE2D_DESC::default();
                unsafe {
                    existing.GetDesc(&mut existing_desc);
                }
                existing_desc.Width != source_desc.Width
                    || existing_desc.Height != source_desc.Height
                    || existing_desc.Format != source_desc.Format
            }
            None => true,
        };

        if needs_recreate {
            source_desc.Usage = D3D11_USAGE_STAGING;
            source_desc.BindFlags = 0;
            source_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
            source_desc.MiscFlags = 0;

            let mut texture = None;
            unsafe {
                self.device
                    .CreateTexture2D(&source_desc, None, Some(&mut texture))?;
            }
            let texture = texture.ok_or_else(|| {
                WindowsError::new(
                    E_FAIL.into(),
                    "CreateTexture2D returned no texture".into(),
                )
            })?;
            self.staging_texture = Some(texture);
        }

        self.staging_texture.clone().ok_or_else(|| {
            WindowsError::new(
                E_FAIL.into(),
                "staging texture unavailable after creation".into(),
            )
        })
    }
}

#[derive(Debug)]
struct FrameReleaseGuard {
    duplication: IDXGIOutputDuplication,
}

impl FrameReleaseGuard {
    fn new(duplication: IDXGIOutputDuplication) -> Self {
        Self { duplication }
    }
}

impl Drop for FrameReleaseGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = self.duplication.ReleaseFrame();
        }
    }
}

#[derive(Debug)]
struct MapUnmapGuard {
    context: ID3D11DeviceContext,
    resource: ID3D11Resource,
}

impl MapUnmapGuard {
    fn new(context: ID3D11DeviceContext, resource: ID3D11Resource) -> Self {
        Self { context, resource }
    }
}

impl Drop for MapUnmapGuard {
    fn drop(&mut self) {
        unsafe {
            self.context.Unmap(&self.resource, 0);
        }
    }
}

fn create_d3d11_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    unsafe {
        let mut device = None;
        let mut context = None;
        let mut feature_level = D3D_FEATURE_LEVEL(0);

        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut feature_level),
            Some(&mut context),
        )
        .context("D3D11CreateDevice failed")?;

        let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice returned no device"))?;
        let context = context.ok_or_else(|| anyhow!("D3D11CreateDevice returned no context"))?;

        Ok((device, context))
    }
}

fn create_output_duplication(device: &ID3D11Device) -> Result<IDXGIOutputDuplication> {
    unsafe {
        let dxgi_device: IDXGIDevice = device.cast().context("ID3D11Device -> IDXGIDevice")?;
        let adapter: IDXGIAdapter = dxgi_device.GetAdapter().context("GetAdapter failed")?;
        let output: IDXGIOutput = adapter.EnumOutputs(0).context("EnumOutputs(0) failed")?;
        let output1: IDXGIOutput1 = output.cast().context("IDXGIOutput -> IDXGIOutput1")?;

        output1
            .DuplicateOutput(device)
            .context("DuplicateOutput failed")
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

#[cfg(test)]
mod tests {
    use super::{copy_bgra_into_u32, normalize_position, ViewerFrame};

    #[test]
    fn normalize_position_clamps_values() {
        assert_eq!(normalize_position(-10.0, 100), 0.0);
        assert_eq!(normalize_position(200.0, 100), 1.0);
        assert_eq!(normalize_position(0.0, 1), 0.0);
    }

    #[test]
    fn copy_bgra_into_u32_converts_colors() {
        let frame = ViewerFrame {
            width: 2,
            height: 1,
            stride: 8,
            pixels: vec![
                0x10, 0x20, 0x30, 0xFF,
                0xAA, 0xBB, 0xCC, 0xFF,
            ],
        };
        let mut output = vec![0_u32; 2];

        copy_bgra_into_u32(&frame, &mut output).expect("copy should succeed");

        assert_eq!(output[0], 0xFF30_2010);
        assert_eq!(output[1], 0xFFCC_BBAA);
    }

    #[test]
    fn copy_bgra_into_u32_rejects_short_payload() {
        let frame = ViewerFrame {
            width: 2,
            height: 2,
            stride: 8,
            pixels: vec![0_u8; 8],
        };
        let mut output = vec![0_u32; 4];

        let error = copy_bgra_into_u32(&frame, &mut output).expect_err("short payload must fail");
        assert!(error.to_string().contains("invalid frame payload size"));
    }
}