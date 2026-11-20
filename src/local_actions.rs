//! Explicitly started *local* macro capture/playback for XLINK users.
//! No hidden hooks or autostart. Capturing global input can include sensitive
//! keystrokes, so the UI must prominently warn before the user opts in.
//! Pause/Break always stops capture/playback even when the XLINK UI is not focused.
use crate::actions::{self, Action, Recorder};
use anyhow::{Context, Result};
use nexus_input::{InputController, SessionState};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::POINT;
use windows::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
};

fn pressed(key: i32) -> bool {
    (unsafe { GetAsyncKeyState(key) } as u16 & 0x8000) != 0
}

/// Runs on its own foreground worker only after a visible confirmation.
pub fn record_global_input(stop: Arc<AtomicBool>) -> Result<(PathBuf, u64)> {
    let mut writer = Recorder::start()?;
    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) }.max(1) as f32;
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) }.max(1) as f32;
    let mut keys = [false; 256];
    let mut buttons = [false; 3];
    let mut previous: Option<(i32,i32)> = None;
    while !stop.load(Ordering::Acquire) {
        if pressed(0x13) { // Pause/Break — independent of XLINK window focus.
            stop.store(true, Ordering::Release);
            break;
        }
        let mut pos = POINT::default();
        if unsafe { GetCursorPos(&mut pos) }.is_ok() {
            let next = (pos.x,pos.y);
            if previous != Some(next) {
                writer.push(Action::Move {
                    x_norm: (pos.x as f32 / (width - 1.0).max(1.0)).clamp(0.0,1.0),
                    y_norm: (pos.y as f32 / (height - 1.0).max(1.0)).clamp(0.0,1.0),
                })?;
                previous = Some(next);
            }
        }
        for (idx,key) in [0x01,0x02,0x04].into_iter().enumerate() {
            let current = pressed(key);
            if current != buttons[idx] {
                writer.push(Action::Button {button:idx as u8,pressed:current})?;
                buttons[idx] = current;
            }
        }
        for key in 8..=254 {
            // Avoid replaying the Windows Secure Attention sequence, and
            // avoid recording the emergency Pause/Break command itself.
            if key == 0x13 || key == 0x5B || key == 0x5C {continue;}
            let current = pressed(key as i32);
            if current != keys[key] {
                writer.push(Action::Key {virtual_key:key as u16,pressed:current})?;
                keys[key]=current;
            }
        }
        thread::sleep(Duration::from_millis(7));
    }
    writer.finish()
}

pub async fn play_local(
    path: PathBuf,
    repeats: Option<u32>,
    stop: Arc<AtomicBool>,
) -> Result<u64> {
    let input = Arc::new(InputController::new()
        .context("cannot initialize local input playback")?);
    input.set_state(SessionState::Active);
    let emergency = Arc::clone(&stop);
    let watcher = tokio::spawn(async move {
        while !emergency.load(Ordering::Acquire) {
            if pressed(0x13) {
                emergency.store(true, Ordering::Release);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let input_for_replay = Arc::clone(&input);
    let result = actions::replay(&path, repeats, &stop, move |action| {
        let input = Arc::clone(&input_for_replay);
        async move {
            match action {
                Action::Move { x_norm,y_norm } => {
                    input.inject_mouse_move(x_norm,y_norm)?;
                }
                Action::Button {button,pressed} => {
                    input.inject_mouse_button(button,pressed)?;
                }
                Action::Key {virtual_key,pressed} => {
                    input.inject_virtual_key_event(virtual_key,pressed)?;
                }
            }
            Ok(())
        }
    }).await;
    stop.store(true,Ordering::Release);
    watcher.abort();
    input.set_state(SessionState::Inactive); // Releases every held key/button.
    result
}
