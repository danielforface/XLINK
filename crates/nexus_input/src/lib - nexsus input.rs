use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicU8, Ordering};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_VIRTUALDESK,
};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

pub const WINDOWS_ABSOLUTE_MAX: i32 = 65_535;
const SESSION_INACTIVE: u8 = 0;
const SESSION_PENDING: u8 = 1;
const SESSION_ACTIVE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Inactive,
    PendingConsent,
    Active,
}

#[derive(Debug, Clone)]
pub struct MousePreview {
    pub absolute_x: i32,
    pub absolute_y: i32,
    pub desktop_x: i32,
    pub desktop_y: i32,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct KeyboardPreview {
    pub virtual_key: Option<u16>,
    pub scan_code: Option<u16>,
    pub pressed: bool,
    pub flags: u32,
}

#[derive(Debug)]
pub struct InputController {
    desktop_width: i32,
    desktop_height: i32,
    state: AtomicU8,
}

impl InputController {
    pub fn new() -> Result<Self> {
        let (desktop_width, desktop_height) = desktop_dimensions()
            .ok_or_else(|| anyhow!("failed to query desktop dimensions"))?;

        Ok(Self {
            desktop_width,
            desktop_height,
            state: AtomicU8::new(SESSION_INACTIVE),
        })
    }

    pub fn set_state(&self, state: SessionState) {
        self.state.store(state_to_u8(state), Ordering::Release);
    }

    pub fn state(&self) -> SessionState {
        u8_to_state(self.state.load(Ordering::Acquire))
    }

    pub fn preview_mouse_move(&self, normalized_x: f32, normalized_y: f32) -> Result<MousePreview> {
        self.ensure_active()?;

        if !normalized_x.is_finite() || !normalized_y.is_finite() {
            return Err(anyhow!("normalized coordinates must be finite"));
        }

        let clamped_x = normalized_x.clamp(0.0, 1.0);
        let clamped_y = normalized_y.clamp(0.0, 1.0);
        let absolute_x = (clamped_x * WINDOWS_ABSOLUTE_MAX as f32).round() as i32;
        let absolute_y = (clamped_y * WINDOWS_ABSOLUTE_MAX as f32).round() as i32;
        let desktop_x = ((self.desktop_width.saturating_sub(1)) as f32 * clamped_x).round() as i32;
        let desktop_y = ((self.desktop_height.saturating_sub(1)) as f32 * clamped_y).round() as i32;
        let flags = MOUSEEVENTF_MOVE.0 | MOUSEEVENTF_ABSOLUTE.0 | MOUSEEVENTF_VIRTUALDESK.0;

        Ok(MousePreview {
            absolute_x,
            absolute_y,
            desktop_x,
            desktop_y,
            flags,
        })
    }

    pub fn preview_virtual_key_event(
        &self,
        virtual_key: u16,
        pressed: bool,
    ) -> Result<KeyboardPreview> {
        self.ensure_active()?;

        if virtual_key == 0 {
            return Err(anyhow!("virtual key must be non-zero"));
        }

        let flags = if pressed { 0 } else { KEYEVENTF_KEYUP.0 };
        Ok(KeyboardPreview {
            virtual_key: Some(virtual_key),
            scan_code: None,
            pressed,
            flags,
        })
    }

    pub fn preview_scan_code_event(&self, scan_code: u16, pressed: bool) -> Result<KeyboardPreview> {
        self.ensure_active()?;

        if scan_code == 0 {
            return Err(anyhow!("scan code must be non-zero"));
        }

        let mut flags = KEYEVENTF_SCANCODE.0;
        if !pressed {
            flags |= KEYEVENTF_KEYUP.0;
        }

        Ok(KeyboardPreview {
            virtual_key: None,
            scan_code: Some(scan_code),
            pressed,
            flags,
        })
    }

    pub fn desktop_size(&self) -> (i32, i32) {
        (self.desktop_width, self.desktop_height)
    }

    fn ensure_active(&self) -> Result<()> {
        if self.state() == SessionState::Active {
            Ok(())
        } else {
            Err(anyhow!(
                "input mapping is disabled while session state is {:?}",
                self.state()
            ))
        }
    }
}

fn desktop_dimensions() -> Option<(i32, i32)> {
    unsafe {
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        if width > 0 && height > 0 {
            Some((width, height))
        } else {
            None
        }
    }
}

fn state_to_u8(state: SessionState) -> u8 {
    match state {
        SessionState::Inactive => SESSION_INACTIVE,
        SessionState::PendingConsent => SESSION_PENDING,
        SessionState::Active => SESSION_ACTIVE,
    }
}

fn u8_to_state(value: u8) -> SessionState {
    match value {
        SESSION_PENDING => SessionState::PendingConsent,
        SESSION_ACTIVE => SessionState::Active,
        _ => SessionState::Inactive,
    }
}