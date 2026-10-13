use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Ctrl,
    Shift,
    Alt,
    Super,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Letter(char),
    Insert,
}

/// The key combination sent to the focused app to make it paste, parsed from
/// config strings like "Ctrl+V", "Ctrl+Shift+V" or "Shift+Insert".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteKeys {
    pub modifiers: Vec<Modifier>,
    pub key: Key,
}

impl PasteKeys {
    pub fn parse(s: &str) -> Result<Self> {
        let mut modifiers = Vec::new();
        let mut key = None;
        for part in s.split('+').map(str::trim).filter(|p| !p.is_empty()) {
            let lower = part.to_ascii_lowercase();
            let modifier = match lower.as_str() {
                "ctrl" | "control" => Some(Modifier::Ctrl),
                "shift" => Some(Modifier::Shift),
                "alt" => Some(Modifier::Alt),
                "super" | "meta" | "win" => Some(Modifier::Super),
                _ => None,
            };
            if let Some(m) = modifier {
                if !modifiers.contains(&m) {
                    modifiers.push(m);
                }
                continue;
            }
            if key.is_some() {
                bail!("paste keys '{s}' have more than one non-modifier key");
            }
            key = Some(match lower.as_str() {
                "insert" | "ins" => Key::Insert,
                l if l.len() == 1 && l.as_bytes()[0].is_ascii_lowercase() => {
                    Key::Letter(l.as_bytes()[0] as char)
                }
                _ => bail!("unsupported paste key '{part}'"),
            });
        }
        let key = key.ok_or_else(|| anyhow!("paste keys '{s}' have no key"))?;
        Ok(Self { modifiers, key })
    }
}

/// evdev keycode (linux/input-event-codes.h) for the key at a US-layout
/// position. uinput sends positions, not characters.
pub fn evdev_code(key: Key) -> u16 {
    match key {
        Key::Insert => 110,
        Key::Letter(c) => {
            const ROWS: [(&str, u16); 3] = [("qwertyuiop", 16), ("asdfghjkl", 30), ("zxcvbnm", 44)];
            ROWS.iter()
                .find_map(|(row, first)| row.find(c).map(|i| first + i as u16))
                .expect("PasteKeys only holds a-z")
        }
    }
}

pub fn evdev_modifier(m: Modifier) -> u16 {
    match m {
        Modifier::Ctrl => 29,
        Modifier::Shift => 42,
        Modifier::Alt => 56,
        Modifier::Super => 125,
    }
}

pub fn x11_keysym(key: Key) -> u32 {
    match key {
        Key::Insert => 0xff63,
        Key::Letter(c) => c as u32,
    }
}

pub fn x11_modifier_keysym(m: Modifier) -> u32 {
    match m {
        Modifier::Ctrl => 0xffe3,
        Modifier::Shift => 0xffe1,
        Modifier::Alt => 0xffe9,
        Modifier::Super => 0xffeb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ctrl_v() {
        let k = PasteKeys::parse("Ctrl+V").unwrap();
        assert_eq!(k.modifiers, vec![Modifier::Ctrl]);
        assert_eq!(k.key, Key::Letter('v'));
    }

    #[test]
    fn parses_terminal_and_insert_variants() {
        let k = PasteKeys::parse("ctrl+shift+v").unwrap();
        assert_eq!(k.modifiers, vec![Modifier::Ctrl, Modifier::Shift]);
        let k = PasteKeys::parse("Shift+Insert").unwrap();
        assert_eq!(k.key, Key::Insert);
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(PasteKeys::parse("Ctrl").is_err());
        assert!(PasteKeys::parse("Ctrl+V+C").is_err());
        assert!(PasteKeys::parse("Ctrl+;").is_err());
        assert!(PasteKeys::parse("Ctrl+F5").is_err());
    }

    #[test]
    fn evdev_codes_match_input_event_codes() {
        assert_eq!(evdev_code(Key::Letter('v')), 47);
        assert_eq!(evdev_code(Key::Letter('q')), 16);
        assert_eq!(evdev_code(Key::Letter('a')), 30);
        assert_eq!(evdev_code(Key::Letter('m')), 50);
        assert_eq!(evdev_code(Key::Insert), 110);
    }
}
