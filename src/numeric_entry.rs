//! Numeric session-code editor with explicit slot semantics.
//!
//! Only ASCII digits are stored. A cursor represents the next slot to edit;
//! insertion overwrites an existing slot or appends to the contiguous code.
//! UI code calls these pure functions for keyboard, pointer and keypad input.
pub const MIN_CODE_DIGITS: usize = 8;
pub const MAX_CODE_DIGITS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditAction {
    Digit(char),
    Backspace,
    Delete,
    Clear,
    Left,
    Right,
    Home,
    End,
}

pub fn normalize(raw: &str) -> String {
    raw.chars()
        .filter(char::is_ascii_digit)
        .take(MAX_CODE_DIGITS)
        .collect()
}

pub fn position(code: &str, slot: usize) -> usize {
    slot.min(code.len()).min(MAX_CODE_DIGITS)
}

pub fn apply(code: &mut String, cursor: &mut usize, action: EditAction) -> bool {
    *code = normalize(code);
    *cursor = position(code, *cursor);
    let before = code.clone();
    match action {
        EditAction::Digit(digit) if digit.is_ascii_digit() => {
            if *cursor < code.len() {
                code.replace_range(*cursor..*cursor + 1, &digit.to_string());
                *cursor += 1;
            } else if code.len() < MAX_CODE_DIGITS {
                code.push(digit);
                *cursor += 1;
            }
        }
        EditAction::Digit(_) => {}
        EditAction::Backspace if *cursor > 0 => {
            *cursor -= 1;
            code.remove(*cursor);
        }
        EditAction::Delete if *cursor < code.len() => {
            code.remove(*cursor);
        }
        EditAction::Clear => {
            code.clear();
            *cursor = 0;
        }
        EditAction::Left => *cursor = cursor.saturating_sub(1),
        EditAction::Right => *cursor = (*cursor + 1).min(code.len()),
        EditAction::Home => *cursor = 0,
        EditAction::End => *cursor = code.len(),
        _ => {}
    }
    *cursor = position(code, *cursor);
    *code != before
}

pub fn paste(code: &mut String, cursor: &mut usize, text: &str) -> bool {
    let digits = normalize(text);
    let mut changed = false;
    for digit in digits.chars() {
        changed |= apply(code, cursor, EditAction::Digit(digit));
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_typing_advances_and_never_exceeds_ten_digits() {
        let mut code = String::new();
        let mut cursor = 0;
        for digit in "0123456789123".chars() {
            apply(&mut code, &mut cursor, EditAction::Digit(digit));
        }
        assert_eq!(code, "0123456789");
        assert_eq!(cursor, 10);
    }

    #[test]
    fn editing_existing_slot_replaces_then_advances() {
        let mut code = "12345678".to_string();
        let mut cursor = position(&code, 3);
        apply(&mut code, &mut cursor, EditAction::Digit('9'));
        assert_eq!(code, "12395678");
        assert_eq!(cursor, 4);
    }

    #[test]
    fn backspace_returns_to_previous_slot_and_shifts_remaining_digits() {
        let mut code = "12345678".to_string();
        let mut cursor = 5;
        apply(&mut code, &mut cursor, EditAction::Backspace);
        assert_eq!(code, "1234678");
        assert_eq!(cursor, 4);
        apply(&mut code, &mut cursor, EditAction::Digit('5'));
        assert_eq!(code, "1234578");
        assert_eq!(cursor, 5);
    }

    #[test]
    fn delete_clears_active_digit_and_keeps_cursor() {
        let mut code = "12345678".to_string();
        let mut cursor = 3;
        apply(&mut code, &mut cursor, EditAction::Delete);
        assert_eq!(code, "1235678");
        assert_eq!(cursor, 3);
    }

    #[test]
    fn pasting_formatted_code_keeps_only_ascii_digits() {
        let mut code = String::new();
        let mut cursor = 0;
        paste(&mut code, &mut cursor, "12 34-56\n78 🖼 90");
        assert_eq!(code, "1234567890");
        assert_eq!(cursor, 10);
    }

    #[test]
    fn empty_backspace_and_cursor_movement_are_safe() {
        let mut code = String::new();
        let mut cursor = 7;
        apply(&mut code, &mut cursor, EditAction::Backspace);
        assert!(code.is_empty());
        assert_eq!(cursor, 0);
        apply(&mut code, &mut cursor, EditAction::Right);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn clearing_resets_cursor_for_immediate_fresh_entry() {
        let mut code = "1234567890".to_string();
        let mut cursor = 10;
        apply(&mut code, &mut cursor, EditAction::Clear);
        assert_eq!(cursor, 0);
        assert_eq!(code, "");
    }
}
