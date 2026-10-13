use anyhow::Context;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode,
    SelectionNotifyEvent, SelectionRequestEvent, WindowClass, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, CURRENT_TIME};

use super::serve::{report, Content, READ, READY};

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
    let offered: Vec<Atom> = content
        .mimes
        .iter()
        .map(|m| intern(&conn, m))
        .collect::<anyhow::Result<_>>()?;

    conn.set_selection_owner(window, clipboard, CURRENT_TIME)?;
    let owner = conn.get_selection_owner(clipboard)?.reply()?.owner;
    anyhow::ensure!(owner == window, "could not take ownership of the X11 clipboard");
    report(READY);

    let mut target_list = offered.clone();
    target_list.push(targets);

    loop {
        match conn.wait_for_event()? {
            Event::SelectionRequest(req) => {
                let served = respond(&conn, &req, targets, &target_list, &offered, content);
                if served && req.target != targets {
                    report(READ);
                }
            }
            Event::SelectionClear(ev) if ev.selection == clipboard => return Ok(()),
            _ => {}
        }
    }
}

fn respond(
    conn: &RustConnection,
    req: &SelectionRequestEvent,
    targets: Atom,
    target_list: &[Atom],
    offered: &[Atom],
    content: &Content,
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
    } else if offered.contains(&req.target) {
        conn.change_property8(
            PropMode::REPLACE,
            req.requestor,
            property,
            req.target,
            &content.data,
        )
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
