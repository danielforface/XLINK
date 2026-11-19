//! Responsive 2026-style egui interaction primitives: pixel-perfect alignment,
//! keyboard-friendly code slots, hover feedback, and font-independent vector icons.
use eframe::egui;
use egui::{Align2, Color32, FontId, Pos2, Rect, Response, Rounding, Sense, Stroke, Vec2};
use crate::numeric_entry::{self, EditAction};

const INK: Color32 = Color32::from_rgb(30, 48, 74);
const MUTED: Color32 = Color32::from_rgb(133, 148, 170);
const BLUE: Color32 = Color32::from_rgb(34, 105, 220);
const OUTLINE: Color32 = Color32::from_rgb(214, 225, 242);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    Copy,
    Backspace,
    Settings,
    Logs,
    Stop,
    Connect,
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

pub fn paint_glyph(p: &egui::Painter, glyph: Glyph, center: Pos2, color: Color32) {
    let s = Stroke::new(1.7, color);
    match glyph {
        Glyph::Copy => {
            p.rect_stroke(
                Rect::from_min_max(
                    center + egui::vec2(-6.0, -4.0),
                    center + egui::vec2(5.0, 7.0),
                ), Rounding::same(2.2), s,
            );
            p.line_segment([
                center + egui::vec2(-4.0, -7.5),
                center + egui::vec2(7.5, -7.5),
            ], s);
            p.line_segment([
                center + egui::vec2(7.5, -7.5),
                center + egui::vec2(7.5, 4.0),
            ], s);
        }
        Glyph::Backspace => {
            p.add(egui::Shape::closed_line(vec![
                center + egui::vec2(-8.0, 0.0),
                center + egui::vec2(-2.0, -6.5),
                center + egui::vec2(8.0, -6.5),
                center + egui::vec2(8.0, 6.5),
                center + egui::vec2(-2.0, 6.5),
            ], s));
            p.line_segment([
                center + egui::vec2(0.0, -2.9),
                center + egui::vec2(5.0, 2.9),
            ], s);
            p.line_segment([
                center + egui::vec2(5.0, -2.9),
                center + egui::vec2(0.0, 2.9),
            ], s);
        }
        Glyph::Logs => {
            p.rect_stroke(
                Rect::from_center_size(center, egui::vec2(14.5, 16.0)),
                Rounding::same(2.0), s,
            );
            for y in [-4.0, 0.0, 4.0] {
                p.circle_filled(center + egui::vec2(-4.0, y), 0.9, color);
                p.line_segment([
                    center + egui::vec2(-1.5, y),
                    center + egui::vec2(4.5, y),
                ], s);
            }
        }
        Glyph::Settings => {
            let r1 = 6.8;
            let r2 = 9.0;
            for i in 0..8 {
                let a = (i as f32) * std::f32::consts::TAU / 8.0;
                p.line_segment([
                    center + egui::vec2(a.cos(), a.sin()) * r1,
                    center + egui::vec2(a.cos(), a.sin()) * r2,
                ], Stroke::new(2.8, color));
            }
            p.circle_stroke(center, 6.0, s);
            p.circle_stroke(center, 2.25, s);
        }
        Glyph::Stop => {
            p.rect_filled(
                Rect::from_center_size(center, egui::vec2(11.0, 11.0)),
                Rounding::same(2.0), color,
            );
        }
        Glyph::Connect => {
            let left = center + egui::vec2(-3.5, 3.0);
            let right = center + egui::vec2(3.5, -3.0);
            p.circle_stroke(left, 4.5, s);
            p.circle_stroke(right, 4.5, s);
            p.line_segment([
                center + egui::vec2(-3.0, 2.8),
                center + egui::vec2(3.0, -2.8),
            ], Stroke::new(2.3, color));
        }
    }
}

fn surface(ui: &mut egui::Ui, rect: Rect, response: &Response, selected: bool, danger: bool) {
    let hover = ui.ctx().animate_bool(response.id.with("hover"), response.hovered());
    let press = ui.ctx().animate_bool(response.id.with("pressed"), response.is_pointer_button_down_on());
    let idle = if danger {
        Color32::from_rgb(255, 241, 242)
    } else if selected {
        Color32::from_rgb(226, 237, 255)
    } else {
        Color32::from_rgb(245, 248, 253)
    };
    let highlight = if danger {
        Color32::from_rgb(255, 229, 232)
    } else {
        Color32::from_rgb(227, 238, 255)
    };
    let rect = rect.translate(egui::vec2(0.0, press * 1.0));
    if !selected && !danger {
        ui.painter().rect_filled(
            rect.translate(egui::vec2(0.0, 1.5)),
            Rounding::same(11.0),
            Color32::from_rgba_unmultiplied(45, 76, 128, (13.0 * hover) as u8),
        );
    }
    ui.painter().rect_filled(rect, Rounding::same(11.0), blend(idle, highlight, hover));
    ui.painter().rect_stroke(
        rect,
        Rounding::same(11.0),
        Stroke::new(1.0, if selected {
            Color32::from_rgb(174, 204, 250)
        } else {
            blend(OUTLINE, Color32::from_rgb(175, 203, 242), hover)
        }),
    );
}

pub fn icon_button(ui: &mut egui::Ui, glyph: Glyph, tooltip: &str) -> Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(34.0, 34.0), Sense::click());
    surface(ui, rect, &response, false, false);
    paint_glyph(ui.painter(), glyph, rect.center(), INK);
    response.on_hover_text(tooltip)
}

pub fn toolbar_button(
    ui: &mut egui::Ui, glyph: Glyph, label: &str, selected: bool, danger: bool,
) -> Response {
    let width = 45.0 + label.chars().count() as f32 * 7.1;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 35.0), Sense::click());
    surface(ui, rect, &response, selected, danger);
    let ink = if danger { Color32::from_rgb(180, 58, 67) } else { INK };
    paint_glyph(ui.painter(), glyph, rect.left_center() + egui::vec2(21.0, 0.0), ink);
    ui.painter().text(
        rect.left_center() + egui::vec2(39.0, 0.0),
        Align2::LEFT_CENTER,
        label, FontId::proportional(12.3), ink,
    );
    response
}

pub fn numeric_key(ui: &mut egui::Ui, text: &str, width: f32, height: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width.max(34.0), height), Sense::click()
    );
    surface(ui, rect, &response, false, false);
    if text == "Backspace" {
        paint_glyph(ui.painter(), Glyph::Backspace, rect.center(), INK);
    } else {
        let text_style = if text == "Clear" {
            FontId::proportional(12.0)
        } else {
            FontId::proportional(21.0)
        };
        ui.painter().text(
            rect.center(), Align2::CENTER_CENTER, text, text_style,
            if text == "Clear" { MUTED } else { INK },
        );
    }
    response
}

pub fn connect_button(ui: &mut egui::Ui, width: f32, enabled: bool) -> Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width.max(130.0), 46.0), Sense::click(),
    );
    let hover = ui.ctx().animate_bool(response.id.with("hover"), response.hovered() && enabled);
    let bg = if enabled {
        blend(Color32::from_rgb(30, 100, 218), Color32::from_rgb(16, 80, 202), hover)
    } else {
        Color32::from_rgb(161, 190, 236)
    };
    ui.painter().rect_filled(rect, Rounding::same(12.0), bg);
    let center = rect.center();
    paint_glyph(ui.painter(), Glyph::Connect, center - egui::vec2(79.0, 0.0), Color32::WHITE);
    ui.painter().text(
        center + egui::vec2(10.0, 0.0),
        Align2::CENTER_CENTER,
        "Connect securely", FontId::proportional(15.0), Color32::WHITE,
    );
    if enabled { response } else { response.on_hover_text("Enter 8–10 digits to connect") }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NumericMetrics {
    pub entry_width: f32,
    pub slots_width: f32,
    pub slot_width: f32,
    pub keypad_width: f32,
    pub key_width: f32,
    pub gap: f32,
}

pub fn metrics(content_width: f32) -> NumericMetrics {
    let entry_width = content_width.max(230.0);
    let gap = if entry_width < 340.0 { 4.0 } else { 6.0 };
    let slots_width = entry_width.min(390.0);
    let slot_width = (slots_width - gap * 9.0) / 10.0;
    let keypad_width = entry_width.min(318.0);
    let key_width = (keypad_width - 2.0 * 9.0) / 3.0;
    NumericMetrics {
        entry_width, slots_width, slot_width, keypad_width, key_width, gap,
    }
}

/// Exact centering inside the *current card*, not relative to the application
/// viewport or to an unconstrained egui Grid.
pub fn centered_row<R>(
    ui: &mut egui::Ui,
    desired_width: f32,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    ui.horizontal(|ui| {
        let space = (ui.available_width() - desired_width).max(0.0) * 0.5;
        if space > 0.0 { ui.add_space(space); }
        contents(ui)
    }).inner
}

pub struct SlotResult {
    pub submit: bool,
}

pub fn code_slots(
    ui: &mut egui::Ui,
    code: &mut String,
    cursor: &mut usize,
    refocus: bool,
    enabled: bool,
    width: f32,
) -> SlotResult {
    let m = metrics(width);
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(m.slots_width, 57.0),
        Sense::click(),
    );
    if refocus && enabled { response.request_focus(); }
    if response.clicked() && enabled {
        response.request_focus();
        if let Some(pos) = response.interact_pointer_pos() {
            let step = m.slot_width + m.gap;
            let idx = ((pos.x - rect.left()) / step).floor().max(0.0) as usize;
            *cursor = numeric_entry::position(code, idx);
        }
    }
    let focused = response.has_focus() && enabled;
    let mut submit = false;

    if focused {
        let events = ui.input(|i| i.events.clone());
        for event in events {
            match event {
                egui::Event::Text(text) => {
                    // Process individual characters; ignore non-ASCII numeric
                    // scripts to keep public pairing codes interoperable.
                    for c in text.chars().filter(char::is_ascii_digit) {
                        numeric_entry::apply(code, cursor, EditAction::Digit(c));
                    }
                }
                egui::Event::Paste(text) => {
                    numeric_entry::paste(code, cursor, &text);
                }
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if modifiers.command && key == egui::Key::A {
                        numeric_entry::apply(code, cursor, EditAction::Clear);
                        continue;
                    }
                    let action = match key {
                        egui::Key::Backspace => Some(EditAction::Backspace),
                        egui::Key::Delete => Some(EditAction::Delete),
                        egui::Key::ArrowLeft => Some(EditAction::Left),
                        egui::Key::ArrowRight => Some(EditAction::Right),
                        egui::Key::Home => Some(EditAction::Home),
                        egui::Key::End => Some(EditAction::End),
                        egui::Key::Escape => Some(EditAction::Clear),
                        egui::Key::Enter => { submit = true; None }
                        _ => None,
                    };
                    if let Some(action) = action {
                        numeric_entry::apply(code, cursor, action);
                    }
                }
                _ => {}
            }
        }
    }

    // Ten unboxed, underline-only positions. Public mailbox nameplate length
    // varies, so the final two positions are visually optional (8–10 digits).
    // All lines share one baseline; the focused line brightens and thickens
    // without shifting layout or showing a visually noisy input rectangle.
    for i in 0..numeric_entry::MAX_CODE_DIGITS {
        let left = rect.left() + i as f32 * (m.slot_width + m.gap);
        let right = left + m.slot_width;
        let center_x = left + m.slot_width / 2.0;
        let baseline = rect.bottom() - 6.0;
        let is_current = focused && *cursor == i;
        let is_optional = i >= numeric_entry::MIN_CODE_DIGITS;
        let has_digit = code.as_bytes().get(i).is_some();

        let underline = if is_current {
            BLUE
        } else if has_digit {
            Color32::from_rgb(116, 150, 200)
        } else if is_optional {
            Color32::from_rgb(223, 230, 240)
        } else {
            Color32::from_rgb(197, 211, 229)
        };
        // Eased transition driven by focus/selection, independently for each
        // position: no emoji, no font-specific border glyphs.
        let emphasis = ui.ctx().animate_bool(
            response.id.with(("slot", i)), is_current,
        );
        let stroke = Stroke::new(1.45 + emphasis * 1.55, underline);
        ui.painter().line_segment([
            egui::pos2(left + 2.0, baseline),
            egui::pos2(right - 2.0, baseline),
        ], stroke);
        if is_current {
            // Restrained active marker: a small blue caret above the line.
            let blink = ui.input(|input| (input.time * 2.25).sin() > -0.15);
            if blink && !has_digit {
                ui.painter().line_segment([
                    egui::pos2(center_x, baseline - 28.0),
                    egui::pos2(center_x, baseline - 8.0),
                ], Stroke::new(1.55, BLUE));
            }
        }
        if let Some(digit) = code.as_bytes().get(i) {
            ui.painter().text(
                egui::pos2(center_x, baseline - 22.0),
                Align2::CENTER_CENTER,
                (*digit as char).to_string(),
                FontId::proportional(23.0),
                if is_current { BLUE } else { INK },
            );
        }
    }
    SlotResult { submit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responsive_slots_and_keypad_fit_container() {
        for width in [230.0, 250.0, 330.0, 410.0, 700.0] {
            let m = metrics(width);
            assert!(m.slots_width <= width, "slots overflow at {width}");
            assert!(m.keypad_width <= width, "keypad overflow at {width}");
            assert!((10.0 * m.slot_width + 9.0 * m.gap - m.slots_width).abs() < 0.01);
            assert!((3.0 * m.key_width + 18.0 - m.keypad_width).abs() < 0.01);
            assert!(m.slot_width >= 18.0);
        }
    }
}
