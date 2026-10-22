use anyhow::{bail, Context, Result};
use regex::Regex;
use std::os::fd::{AsRawFd, OwnedFd};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_keyboard::{self, KeymapFormat, WlKeyboard};
use wayland_client::protocol::{wl_registry::WlRegistry, wl_seat::WlSeat};
use wayland_client::{delegate_noop, Connection, Dispatch, Proxy, QueueHandle, WEnum};

use super::keys::{x11_keysym, x11_modifier_keysym, Key, Modifier};

// evdev codes are XKB keycodes minus this offset.
const XKB_OFFSET: u16 = 8;

/// The session's key layout, from the XKB keymap the compositor hands every
/// client. uinput sends key positions, so this finds the position that types
/// a symbol on layouts such as Dvorak or AZERTY.
pub struct Layout {
    /// (XKB keycode, levels per group), sorted by keycode.
    keys: Vec<(u16, Vec<Vec<String>>)>,
    /// The layout in use, when the desktop reports it.
    active: Option<usize>,
}

impl Layout {
    pub fn parse(keymap: &str) -> Result<Self> {
        let keycodes_at = keymap.find("xkb_keycodes").context("no xkb_keycodes")?;
        let symbols_at = keymap.find("xkb_symbols").context("no xkb_symbols")?;
        let keycodes_end = keymap[keycodes_at..]
            .find("xkb_types")
            .map_or(keymap.len(), |i| keycodes_at + i);
        let keycodes = &keymap[keycodes_at..keycodes_end];
        let symbols = &keymap[symbols_at..];

        let code_re = Regex::new(r"<([^>]+)>\s*=\s*(\d+)\s*;")?;
        let alias_re = Regex::new(r"alias\s+<([^>]+)>\s*=\s*<([^>]+)>")?;
        let mut codes: std::collections::HashMap<String, u16> = code_re
            .captures_iter(keycodes)
            .filter_map(|c| Some((c[1].to_string(), c[2].parse().ok()?)))
            .collect();
        for c in alias_re.captures_iter(keycodes) {
            if let Some(&code) = codes.get(&c[2]) {
                codes.insert(c[1].to_string(), code);
            }
        }

        let key_re = Regex::new(r"(?s)key\s+<([^>]+)>\s*\{(.*?)\};")?;
        let actions_re = Regex::new(r"actions\[[^\]]*\]\s*=\s*\[[^\]]*\]")?;
        let named_re = Regex::new(r"symbols\[[^\]]*\]\s*=\s*\[([^\]]*)\]")?;
        let bare_re = Regex::new(r"\[([^\]]*)\]")?;
        let mut keys: Vec<(u16, Vec<Vec<String>>)> = key_re
            .captures_iter(symbols)
            .filter_map(|c| {
                let code = *codes.get(&c[1])?;
                let body = actions_re.replace_all(&c[2], "");
                let lists = if body.contains("symbols[") {
                    &named_re
                } else {
                    &bare_re
                };
                let groups = lists
                    .captures_iter(&body)
                    .map(|g| g[1].split(',').map(|s| s.trim().to_string()).collect())
                    .collect();
                Some((code, groups))
            })
            .collect();
        if keys.is_empty() {
            bail!("keymap has no keys");
        }
        keys.sort_by_key(|(code, _)| *code);
        Ok(Self { keys, active: None })
    }

    fn groups(&self) -> usize {
        self.keys.iter().map(|(_, g)| g.len()).max().unwrap_or(0)
    }

    /// evdev code of the key whose first two levels produce `key`, looked up
    /// in the active layout first. Wayland does not tell an unfocused client
    /// which layout is active, so without a desktop-specific answer the
    /// first layout with a match wins.
    pub fn evdev_code(&self, key: Key) -> Option<u16> {
        let name = match key {
            Key::Letter(c) => c.to_string(),
            Key::Insert => "Insert".to_string(),
        };
        self.find(&name, x11_keysym(key), 2)
    }

    /// evdev code of the key that acts as `m`. Options such as
    /// `ctrl:swapcaps` or `altwin:swap_alt_win` move modifiers to other
    /// positions, so the fixed US codes would press the wrong key.
    pub fn modifier_code(&self, m: Modifier) -> Option<u16> {
        let left = x11_modifier_keysym(m);
        let names: [&str; 2] = match m {
            Modifier::Ctrl => ["Control_L", "Control_R"],
            Modifier::Shift => ["Shift_L", "Shift_R"],
            Modifier::Alt => ["Alt_L", "Alt_R"],
            Modifier::Super => ["Super_L", "Super_R"],
        };
        // Each right-hand keysym is the left one plus one.
        names
            .iter()
            .zip([left, left + 1])
            .find_map(|(name, value)| self.find(name, value, 1))
    }

    fn find(&self, name: &str, value: u32, levels: usize) -> Option<u16> {
        // Keysyms appear as names ("v") or as hex values ("0x76").
        let matches = |sym: &String| {
            sym == name
                || sym
                    .strip_prefix("0x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    == Some(value)
        };
        self.active
            .into_iter()
            .chain(0..self.groups())
            .find_map(|group| {
                self.keys
                    .iter()
                    .find(|(_, g)| {
                        g.get(group)
                            .is_some_and(|lv| lv.iter().take(levels).any(&matches))
                    })
                    .and_then(|(code, _)| code.checked_sub(XKB_OFFSET))
            })
    }
}

#[derive(Default)]
struct State {
    keymap: Option<(OwnedFd, usize)>,
}

/// Fetch the keymap the compositor sends with every new wl_keyboard.
pub fn session_layout() -> Result<Layout> {
    let conn = Connection::connect_to_env().context("connect to Wayland")?;
    let (globals, mut queue) = registry_queue_init::<State>(&conn)?;
    let qh = queue.handle();
    let seat = globals
        .bind::<WlSeat, _, _>(&qh, 1..=7, ())
        .context("no Wayland seat")?;
    let keyboard = seat.get_keyboard(&qh, ());
    let mut state = State::default();
    queue.roundtrip(&mut state)?;
    if keyboard.version() >= 3 {
        keyboard.release();
    }

    let (fd, size) = state.keymap.context("compositor sent no keymap")?;
    let mut layout = Layout::parse(&read_keymap(&fd, size)?)?;
    if layout.groups() > 1 {
        layout.active = gnome_active_layout().filter(|&i| i < layout.groups());
        log::debug!("active keyboard layout: {:?}", layout.active);
    }
    Ok(layout)
}

/// GNOME builds the keymap from `sources` in order and keeps the active one
/// first in `mru-sources`.
fn gnome_active_layout() -> Option<usize> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if !desktop.to_ascii_lowercase().contains("gnome") {
        return None;
    }
    let read = |key: &str| {
        std::process::Command::new("gsettings")
            .args(["get", "org.gnome.desktop.input-sources", key])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let sources = parse_sources(&read("sources")?);
    let active = parse_sources(&read("mru-sources")?).into_iter().next()?;
    sources.iter().position(|s| *s == active)
}

/// `[('xkb', 'us+dvorak'), ('xkb', 'it')]` -> ["xkb us+dvorak", "xkb it"].
fn parse_sources(value: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"\('([^']*)',\s*'([^']*)'\)") else {
        return Vec::new();
    };
    re.captures_iter(value)
        .map(|c| format!("{} {}", &c[1], &c[2]))
        .collect()
}

// Compositors share one read-only keymap file between clients, so map it
// instead of moving the shared file offset with read().
fn read_keymap(fd: &OwnedFd, size: usize) -> Result<String> {
    if size == 0 {
        bail!("empty keymap");
    }
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).context("map keymap");
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, size) };
    let text = String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string();
    unsafe {
        libc::munmap(ptr, size);
    }
    Ok(text)
}

impl Dispatch<WlKeyboard, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_keyboard::Event::Keymap {
            format: WEnum::Value(KeymapFormat::XkbV1),
            fd,
            size,
        } = event
        {
            state.keymap = Some((fd, size as usize));
        }
    }
}

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ignore WlSeat);

#[cfg(test)]
mod tests {
    use super::*;

    const US_DVORAK: &str = r#"xkb_keymap {
xkb_keycodes "evdev+aliases(qwerty)" {
	minimum = 8;
	maximum = 255;
	<INS> = 118;
	<AB04> = 55;
	<AB09> = 60;
	<AC01> = 38;
	alias <ALT2> = <AB04>;
	indicator 1 = "Caps Lock";
};
xkb_types "complete" {
	type "ALPHABETIC" { modifiers= Shift+Lock; };
};
xkb_symbols "pc+us+us(dvorak)" {
	name[Group1]="English (US)";
	key <INS> { [ Insert ] };
	key <AB04> {
		type= "ALPHABETIC",
		symbols[Group1]= [ v, V ],
		symbols[Group2]= [ k, K ]
	};
	key <AB09> {
		symbols[Group1]= [ period, greater ],
		symbols[Group2]= [ v, V ]
	};
	key <AC01> { [ a, A ], [ a, A ] };
};
};"#;

    const DVORAK: &str = r#"xkb_keymap {
xkb_keycodes "evdev" {
	<AB04> = 55;
	<AB09> = 60;
};
xkb_symbols "pc+us(dvorak)" {
	key <AB04> { [ k, K ] };
	key <AB09> { [ v, V ] };
};
};"#;

    #[test]
    fn single_dvorak_layout_uses_the_dvorak_v_key() {
        let layout = Layout::parse(DVORAK).unwrap();
        assert_eq!(layout.evdev_code(Key::Letter('v')), Some(52));
    }

    #[test]
    fn first_layout_wins_when_several_have_the_key() {
        let layout = Layout::parse(US_DVORAK).unwrap();
        assert_eq!(layout.evdev_code(Key::Letter('v')), Some(47));
        assert_eq!(layout.evdev_code(Key::Insert), Some(110));
        assert_eq!(layout.evdev_code(Key::Letter('q')), None);
    }

    // GNOME writes keysyms as hex values.
    const HEX_DVORAK_IT: &str = r#"xkb_keymap {
xkb_keycodes "evdev" {
	<AB04> = 55;
	<AB09> = 60;
};
xkb_symbols "pc_us(dvorak)_it_2" {
	key <AB04> {
		symbols[1]= [ 0x6b, 0x4b ],
		symbols[2]= [ 0x76, 0x56, 0xad2, 0xad0 ]
	};
	key <AB09> {
		symbols[1]= [ 0x76, 0x56 ],
		symbols[2]= [ 0x2e, 0x3a ]
	};
};
};"#;

    #[test]
    fn hex_keysyms_match() {
        let layout = Layout::parse(HEX_DVORAK_IT).unwrap();
        assert_eq!(layout.evdev_code(Key::Letter('v')), Some(52));
    }

    #[test]
    fn active_layout_is_tried_first() {
        let mut layout = Layout::parse(HEX_DVORAK_IT).unwrap();
        layout.active = Some(1);
        assert_eq!(layout.evdev_code(Key::Letter('v')), Some(47));
    }

    #[test]
    fn parses_gnome_sources() {
        assert_eq!(
            parse_sources("[('xkb', 'us+dvorak'), ('xkb', 'it')]"),
            vec!["xkb us+dvorak", "xkb it"]
        );
        assert!(parse_sources("@a(ss) []").is_empty());
    }

    // ctrl:swapcaps and altwin:swap_alt_win, as xkbcomp writes them.
    const SWAPPED: &str = r#"xkb_keymap {
xkb_keycodes "evdev" {
	<LCTL> = 37;
	<LALT> = 64;
	<CAPS> = 66;
	<RCTL> = 105;
	<LWIN> = 133;
};
xkb_symbols "pc+us+ctrl(swapcaps)+altwin(swap_alt_win)" {
	key <LCTL> { [ Caps_Lock ] };
	key <LALT> { [ Super_L ] };
	key <CAPS> { [ Control_L ] };
	key <RCTL> { [ Control_R ] };
	key <LWIN> { type= "TWO_LEVEL", [ Alt_L, Meta_L ] };
};
};"#;

    #[test]
    fn modifiers_follow_swap_options() {
        let layout = Layout::parse(SWAPPED).unwrap();
        assert_eq!(layout.modifier_code(Modifier::Ctrl), Some(58));
        assert_eq!(layout.modifier_code(Modifier::Alt), Some(125));
        assert_eq!(layout.modifier_code(Modifier::Super), Some(56));
        assert_eq!(layout.modifier_code(Modifier::Shift), None);
    }

    #[test]
    fn modifiers_match_hex_and_right_hand_keysyms() {
        let hex = "xkb_keycodes { <LCTL> = 37; };\n\
                   xkb_symbols { key <LCTL> { [ 0xffe3 ] }; };";
        let layout = Layout::parse(hex).unwrap();
        assert_eq!(layout.modifier_code(Modifier::Ctrl), Some(29));

        let right = "xkb_keycodes { <RCTL> = 105; };\n\
                     xkb_symbols { key <RCTL> { [ Control_R ] }; };";
        let layout = Layout::parse(right).unwrap();
        assert_eq!(layout.modifier_code(Modifier::Ctrl), Some(97));
    }

    #[test]
    fn rejects_text_without_sections() {
        assert!(Layout::parse("not a keymap").is_err());
    }
}
