use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, Window};
use x11rb::rust_connection::RustConnection;

/// The window the window manager reports as focused, from
/// `_NET_ACTIVE_WINDOW` on the root window.
pub fn active_window(conn: &RustConnection, root: Window) -> Option<Window> {
    let active = conn
        .intern_atom(false, b"_NET_ACTIVE_WINDOW")
        .ok()?
        .reply()
        .ok()?
        .atom;
    conn.get_property(false, root, active, AtomEnum::WINDOW, 0, 1)
        .ok()?
        .reply()
        .ok()?
        .value32()?
        .next()
        .filter(|&w| w != 0)
}
