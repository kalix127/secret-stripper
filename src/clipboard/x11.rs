use anyhow::Context;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SelectionNotifyEvent,
    SelectionRequestEvent, Window, WindowClass, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, CURRENT_TIME};

use super::serve::{report, Content, PASSWORD_HINT_MIME, PASSWORD_HINT_VALUE, READ, READY};

fn intern(conn: &RustConnection, name: &str) -> anyhow::Result<Atom> {
    Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom)
}

pub(super) fn serve(content: &Content) -> anyhow::Result<()> {
    let (conn, screen_num) = x11rb::connect(None).context("connect to X11")?;
    let root = conn.setup().roots[screen_num].root;
    let window = conn.generate_id()?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        window,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new(),
    )?;

    let clipboard = intern(&conn, "CLIPBOARD")?;
    let targets = intern(&conn, "TARGETS")?;
    let hint = intern(&conn, PASSWORD_HINT_MIME)?;
    let mask = conn.setup().resource_id_mask;
    let paste_client = paste_client(&conn, root).map(|w| w & !mask);
    let offered: Vec<Atom> = content
        .mimes
        .iter()
        .map(|m| intern(&conn, m))
        .collect::<anyhow::Result<_>>()?;

    conn.set_selection_owner(window, clipboard, CURRENT_TIME)?;
    let owner = conn.get_selection_owner(clipboard)?.reply()?.owner;
    anyhow::ensure!(
        owner == window,
        "could not take ownership of the X11 clipboard"
    );
    report(READY);

    let mut target_list = offered.clone();
    target_list.extend([hint, targets]);

    loop {
        match conn.wait_for_event()? {
            Event::SelectionRequest(req) => {
                let is_content = offered.contains(&req.target);
                let data = if is_content {
                    Some(content.data.as_slice())
                } else if req.target == hint {
                    Some(PASSWORD_HINT_VALUE)
                } else {
                    None
                };
                let served = respond(&conn, &req, targets, &target_list, data);
                let from_target = paste_client.is_none_or(|c| req.requestor & !mask == c);
                if served && is_content && from_target {
                    report(READ);
                }
            }
            Event::SelectionClear(ev) if ev.selection == clipboard => return Ok(()),
            _ => {}
        }
    }
}

/// The focused window on a plain X11 session. Its client's reads are the
/// paste; other clients are clipboard managers. Under XWayland the focused app
/// may be a Wayland client whose reads arrive through the compositor, so no
/// filtering there.
fn paste_client(conn: &RustConnection, root: Window) -> Option<Window> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return None;
    }
    let active = intern(conn, "_NET_ACTIVE_WINDOW").ok()?;
    conn.get_property(false, root, active, AtomEnum::WINDOW, 0, 1)
        .ok()?
        .reply()
        .ok()?
        .value32()?
        .next()
        .filter(|&w| w != 0)
}

fn respond(
    conn: &RustConnection,
    req: &SelectionRequestEvent,
    targets: Atom,
    target_list: &[Atom],
    data: Option<&[u8]>,
) -> bool {
    // Obsolete clients send property None and expect the target atom to be used.
    let property = if req.property == u32::from(AtomEnum::NONE) {
        req.target
    } else {
        req.property
    };

    let written = if req.target == targets {
        conn.change_property32(
            PropMode::REPLACE,
            req.requestor,
            property,
            AtomEnum::ATOM,
            target_list,
        )
        .is_ok()
    } else if let Some(data) = data {
        conn.change_property8(PropMode::REPLACE, req.requestor, property, req.target, data)
            .is_ok()
    } else {
        false
    };

    let notify = SelectionNotifyEvent {
        response_type: SELECTION_NOTIFY_EVENT,
        sequence: 0,
        time: req.time,
        requestor: req.requestor,
        selection: req.selection,
        target: req.target,
        property: if written {
            property
        } else {
            AtomEnum::NONE.into()
        },
    };
    let sent = conn
        .send_event(false, req.requestor, EventMask::NO_EVENT, notify)
        .is_ok()
        && conn.flush().is_ok();
    written && sent
}
