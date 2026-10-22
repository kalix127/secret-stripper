use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use super::keymap::Layout;
use super::keys::{evdev_code, evdev_modifier, Key, Modifier, PasteKeys};

pub const DEVICE_PATH: &str = "/dev/uinput";

const UI_SET_EVBIT: libc::c_ulong = 0x4004_5564;
const UI_SET_KEYBIT: libc::c_ulong = 0x4004_5565;
const UI_DEV_SETUP: libc::c_ulong = 0x405c_5503;
const UI_DEV_CREATE: libc::c_ulong = 0x5501;
const UI_DEV_DESTROY: libc::c_ulong = 0x5502;

// The kernel's _IO/_IOW encoding for the 'U' (uinput) ioctl type.
const fn uinput_ioc(write: bool, nr: u32, size: usize) -> libc::c_ulong {
    ((write as libc::c_ulong) << 30)
        | ((size as libc::c_ulong) << 16)
        | ((b'U' as libc::c_ulong) << 8)
        | nr as libc::c_ulong
}

const _: () = {
    let int = std::mem::size_of::<libc::c_int>();
    assert!(UI_SET_EVBIT == uinput_ioc(true, 100, int));
    assert!(UI_SET_KEYBIT == uinput_ioc(true, 101, int));
    assert!(UI_DEV_SETUP == uinput_ioc(true, 3, std::mem::size_of::<libc::uinput_setup>()));
    assert!(UI_DEV_CREATE == uinput_ioc(false, 1, 0));
    assert!(UI_DEV_DESTROY == uinput_ioc(false, 2, 0));
};

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const SYN_REPORT: u16 = 0;
const BUS_VIRTUAL: u16 = 0x06;

/// A virtual keyboard created through /dev/uinput. The kernel treats it like
/// real hardware, so every Wayland compositor accepts its key events.
pub struct UinputKeyboard {
    file: File,
    /// Paste keys and modifiers resolved to the positions that type them in
    /// the session layout.
    codes: Vec<(Key, u16)>,
    modifiers: Vec<(Modifier, u16)>,
}

impl UinputKeyboard {
    pub fn create(keys: &[&PasteKeys], layout: Option<&Layout>) -> Result<Self> {
        let codes: Vec<(Key, u16)> = keys
            .iter()
            .map(|k| {
                let code = layout
                    .and_then(|l| l.evdev_code(k.key))
                    .unwrap_or_else(|| evdev_code(k.key));
                log::debug!("paste key {:?} -> evdev {code}", k.key);
                (k.key, code)
            })
            .collect();
        let mut modifiers: Vec<(Modifier, u16)> = Vec::new();
        for &m in keys.iter().flat_map(|k| &k.modifiers) {
            if modifiers.iter().all(|&(seen, _)| seen != m) {
                let code = layout
                    .and_then(|l| l.modifier_code(m))
                    .unwrap_or_else(|| evdev_modifier(m));
                log::debug!("paste modifier {m:?} -> evdev {code}");
                modifiers.push((m, code));
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(DEVICE_PATH)
            .with_context(|| format!("open {DEVICE_PATH}"))?;
        let fd = file.as_raw_fd();

        let mut bits: Vec<u16> = modifiers
            .iter()
            .map(|&(_, code)| code)
            .chain(codes.iter().map(|&(_, code)| code))
            .collect();
        bits.sort_unstable();
        bits.dedup();

        let mut setup: libc::uinput_setup = unsafe { std::mem::zeroed() };
        setup.id.bustype = BUS_VIRTUAL;
        setup.id.vendor = 0x5353;
        setup.id.product = 0x0001;
        setup.id.version = 1;
        for (dst, src) in setup.name.iter_mut().zip(b"secret-stripper paste".iter()) {
            *dst = *src as libc::c_char;
        }

        unsafe {
            check(libc::ioctl(fd, UI_SET_EVBIT, libc::c_int::from(EV_KEY)))?;
            for code in bits {
                check(libc::ioctl(fd, UI_SET_KEYBIT, libc::c_int::from(code)))?;
            }
            check(libc::ioctl(
                fd,
                UI_DEV_SETUP,
                &setup as *const libc::uinput_setup,
            ))?;
            check(libc::ioctl(fd, UI_DEV_CREATE))?;
        }
        Ok(Self {
            file,
            codes,
            modifiers,
        })
    }

    pub fn send(&self, keys: &PasteKeys) -> Result<()> {
        for &m in &keys.modifiers {
            self.key(self.modifier(m), 1)?;
        }
        let code = self
            .codes
            .iter()
            .find(|(key, _)| *key == keys.key)
            .map_or_else(|| evdev_code(keys.key), |&(_, code)| code);
        self.key(code, 1)?;
        self.key(code, 0)?;
        for &m in keys.modifiers.iter().rev() {
            self.key(self.modifier(m), 0)?;
        }
        // Destroying the device right away can drop the trailing releases.
        std::thread::sleep(Duration::from_millis(30));
        Ok(())
    }

    fn modifier(&self, m: Modifier) -> u16 {
        self.modifiers
            .iter()
            .find(|&&(seen, _)| seen == m)
            .map_or_else(|| evdev_modifier(m), |&(_, code)| code)
    }

    fn key(&self, code: u16, value: i32) -> Result<()> {
        self.emit(EV_KEY, code, value)?;
        self.emit(EV_SYN, SYN_REPORT, 0)?;
        std::thread::sleep(Duration::from_millis(5));
        Ok(())
    }

    fn emit(&self, kind: u16, code: u16, value: i32) -> Result<()> {
        let mut event: libc::input_event = unsafe { std::mem::zeroed() };
        event.type_ = kind;
        event.code = code;
        event.value = value;
        let size = std::mem::size_of::<libc::input_event>();
        let written = unsafe {
            libc::write(
                self.file.as_raw_fd(),
                &event as *const libc::input_event as *const libc::c_void,
                size,
            )
        };
        anyhow::ensure!(
            written == size as isize,
            "uinput write failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

impl Drop for UinputKeyboard {
    fn drop(&mut self) {
        unsafe {
            libc::ioctl(self.file.as_raw_fd(), UI_DEV_DESTROY);
        }
    }
}

fn check(ret: libc::c_int) -> Result<()> {
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("uinput ioctl");
    }
    Ok(())
}
