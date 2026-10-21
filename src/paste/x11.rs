use anyhow::{anyhow, Context, Result};
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, Keycode, Window, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::CURRENT_TIME;

use super::keys::{x11_keysym, x11_modifier_keysym, PasteKeys};

const TERMINAL_CLASSES: &[&str] = &[
    "alacritty",
    "blackbox",
    "com.mitchellh.ghostty",
    "foot",
    "gnome-terminal",
    "gnome-terminal-server",
    "guake",
    "kgx",
    "kitty",
    "konsole",
    "lxterminal",
    "mate-terminal",
    "org.gnome.console",
    "org.gnome.ptyxis",
    "org.wezfurlong.wezterm",
    "qterminal",
    "terminator",
    "terminology",
    "tilda",
    "tilix",
    "xfce4-terminal",
    "yakuake",
];

pub struct X11Input {
    conn: RustConnection,
    root: Window,
}

impl X11Input {
    pub fn connect() -> Result<Self> {
        let (conn, screen) = x11rb::connect(None).context("connect to X11")?;
        let root = conn.setup().roots[screen].root;
        Ok(Self { conn, root })
    }

    /// Wait until no modifier key is physically held, so the synthetic paste
    /// is not merged with the chord the user is still pressing.
    pub fn wait_modifiers_released(&self, timeout: Duration) -> Result<()> {
        let mapping = self.conn.get_modifier_mapping()?.reply()?;
        let modifier_codes: Vec<Keycode> =
            mapping.keycodes.into_iter().filter(|&k| k != 0).collect();
        let deadline = Instant::now() + timeout;
        loop {
            let keys = self.conn.query_keymap()?.reply()?.keys;
            let held = modifier_codes
                .iter()
                .any(|&k| keys[usize::from(k / 8)] & (1 << (k % 8)) != 0);
            if !held {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("modifier keys still held after {timeout:?}"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn focused_is_terminal(&self) -> bool {
        self.focused_class()
            .map(|class| {
                TERMINAL_CLASSES
                    .iter()
                    .any(|t| class.eq_ignore_ascii_case(t))
            })
            .unwrap_or(false)
    }

    // WM_CLASS is "instance\0class\0"; the class half is the stable app id.
    fn focused_class(&self) -> Option<String> {
        let active = self
            .conn
            .intern_atom(false, b"_NET_ACTIVE_WINDOW")
            .ok()?
            .reply()
            .ok()?
            .atom;
        let window = self
            .conn
            .get_property(false, self.root, active, AtomEnum::WINDOW, 0, 1)
            .ok()?
            .reply()
            .ok()?
            .value32()?
            .next()?;
        let class = self
            .conn
            .get_property(false, window, AtomEnum::WM_CLASS, AtomEnum::STRING, 0, 256)
            .ok()?
            .reply()
            .ok()?
            .value;
        let class = class.split(|&b| b == 0).nth(1)?;
        Some(String::from_utf8_lossy(class).into_owned())
    }

    pub fn send(&self, keys: &PasteKeys) -> Result<()> {
        let key = self.keycode_for(x11_keysym(keys.key))?;
        let modifiers = keys
            .modifiers
            .iter()
            .map(|&m| self.keycode_for(x11_modifier_keysym(m)))
            .collect::<Result<Vec<_>>>()?;

        for &m in &modifiers {
            self.fake(KEY_PRESS_EVENT, m)?;
        }
        self.fake(KEY_PRESS_EVENT, key)?;
        self.fake(KEY_RELEASE_EVENT, key)?;
        for &m in modifiers.iter().rev() {
            self.fake(KEY_RELEASE_EVENT, m)?;
        }
        self.conn.sync()?;
        Ok(())
    }

    fn fake(&self, kind: u8, keycode: Keycode) -> Result<()> {
        self.conn
            .xtest_fake_input(kind, keycode, CURRENT_TIME, self.root, 0, 0, 0)?;
        Ok(())
    }

    // Resolved through the live keymap so non-US layouts still get the key
    // that produces the wanted symbol. The first two columns are the first
    // layout; a key that types the symbol only in another layout is a last
    // resort, since it types something else while the first is active.
    fn keycode_for(&self, keysym: u32) -> Result<Keycode> {
        let setup = self.conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let mapping = self
            .conn
            .get_keyboard_mapping(min, max - min + 1)?
            .reply()?;
        let per = usize::from(mapping.keysyms_per_keycode);
        let find = |columns: usize| {
            mapping
                .keysyms
                .chunks(per)
                .position(|syms| syms.iter().take(columns).any(|&s| s == keysym))
        };
        find(2)
            .or_else(|| find(per))
            .map(|i| min + i as u8)
            .ok_or_else(|| anyhow!("no keycode produces keysym {keysym:#x}"))
    }
}
