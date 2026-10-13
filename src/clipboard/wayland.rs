use anyhow::Context;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{wl_registry::WlRegistry, wl_seat::WlSeat};
use wayland_client::{
    delegate_noop, event_created_child, Connection, Dispatch, EventQueue, QueueHandle,
};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1::{self as ext_device, ExtDataControlDeviceV1},
    ext_data_control_manager_v1::ExtDataControlManagerV1,
    ext_data_control_offer_v1::ExtDataControlOfferV1,
    ext_data_control_source_v1::{self as ext_source, ExtDataControlSourceV1},
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1::{self as wlr_device, ZwlrDataControlDeviceV1},
    zwlr_data_control_manager_v1::ZwlrDataControlManagerV1,
    zwlr_data_control_offer_v1::ZwlrDataControlOfferV1,
    zwlr_data_control_source_v1::{self as wlr_source, ZwlrDataControlSourceV1},
};

use super::serve::{report, Content, PASSWORD_HINT_MIME, PASSWORD_HINT_VALUE, READ, READY};

enum Manager {
    Ext(ExtDataControlManagerV1),
    Wlr(ZwlrDataControlManagerV1),
}

struct State {
    data: Vec<u8>,
    cancelled: bool,
}

pub(super) struct Owner {
    queue: EventQueue<State>,
    manager: Manager,
    seat: WlSeat,
}

/// Connect and bind a data-control manager. Fails on compositors that expose
/// neither ext- nor wlr-data-control (GNOME), so the caller can fall back.
pub(super) fn connect() -> anyhow::Result<Owner> {
    let conn = Connection::connect_to_env().context("connect to Wayland")?;
    let (globals, queue) = registry_queue_init::<State>(&conn)?;
    let qh = queue.handle();
    let manager = match globals.bind::<ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
        Ok(m) => Manager::Ext(m),
        Err(_) => Manager::Wlr(
            globals
                .bind::<ZwlrDataControlManagerV1, _, _>(&qh, 1..=2, ())
                .context("compositor has no data-control protocol")?,
        ),
    };
    let seat = globals
        .bind::<WlSeat, _, _>(&qh, 1..=9, ())
        .context("no Wayland seat")?;
    Ok(Owner {
        queue,
        manager,
        seat,
    })
}

impl Owner {
    pub(super) fn serve(mut self, content: &Content) -> anyhow::Result<()> {
        let qh = self.queue.handle();
        let mut mimes: Vec<&str> = content.mimes.to_vec();
        mimes.push(PASSWORD_HINT_MIME);
        match &self.manager {
            Manager::Ext(m) => {
                let source = m.create_data_source(&qh, ());
                mimes.iter().for_each(|mime| source.offer(mime.to_string()));
                m.get_data_device(&self.seat, &qh, ())
                    .set_selection(Some(&source));
            }
            Manager::Wlr(m) => {
                let source = m.create_data_source(&qh, ());
                mimes.iter().for_each(|mime| source.offer(mime.to_string()));
                m.get_data_device(&self.seat, &qh, ())
                    .set_selection(Some(&source));
            }
        }

        let mut state = State {
            data: content.data.clone(),
            cancelled: false,
        };
        self.queue.roundtrip(&mut state)?;
        anyhow::ensure!(!state.cancelled, "compositor rejected the clipboard source");
        report(READY);

        while !state.cancelled {
            self.queue.blocking_dispatch(&mut state)?;
        }
        Ok(())
    }
}

impl State {
    fn send(&self, mime_type: &str, fd: OwnedFd) {
        // The fd may arrive non-blocking; a short write would truncate the paste.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let mut file = std::fs::File::from(fd);
        if mime_type == PASSWORD_HINT_MIME {
            let _ = file.write_all(PASSWORD_HINT_VALUE);
        } else if file.write_all(&self.data).is_ok() {
            report(READ);
        }
    }
}

impl Dispatch<ExtDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtDataControlSourceV1,
        event: ext_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_source::Event::Send { mime_type, fd } => state.send(&mime_type, fd),
            ext_source::Event::Cancelled => state.cancelled = true,
            _ => {}
        }
    }
}

impl Dispatch<ZwlrDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwlrDataControlSourceV1,
        event: wlr_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wlr_source::Event::Send { mime_type, fd } => state.send(&mime_type, fd),
            wlr_source::Event::Cancelled => state.cancelled = true,
            _ => {}
        }
    }
}

impl Dispatch<ExtDataControlDeviceV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ExtDataControlDeviceV1,
        event: ext_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_device::Event::DataOffer { id } = event {
            id.destroy();
        }
    }

    event_created_child!(State, ExtDataControlDeviceV1, [
        ext_device::EVT_DATA_OFFER_OPCODE => (ExtDataControlOfferV1, ()),
    ]);
}

impl Dispatch<ZwlrDataControlDeviceV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwlrDataControlDeviceV1,
        event: wlr_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wlr_device::Event::DataOffer { id } = event {
            id.destroy();
        }
    }

    event_created_child!(State, ZwlrDataControlDeviceV1, [
        wlr_device::EVT_DATA_OFFER_OPCODE => (ZwlrDataControlOfferV1, ()),
    ]);
}

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as wayland_client::Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore ExtDataControlManagerV1);
delegate_noop!(State: ignore ZwlrDataControlManagerV1);
delegate_noop!(State: ignore ExtDataControlOfferV1);
delegate_noop!(State: ignore ZwlrDataControlOfferV1);
