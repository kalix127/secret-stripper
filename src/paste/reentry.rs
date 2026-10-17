use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

/// Socket through which a second `paste`, launched while the first one sends
/// its keys, tells the first that those keys fired the chord again. It exists
/// only during the send, which is how a second press is told apart.
pub struct Listener {
    socket: UnixDatagram,
    path: PathBuf,
}

impl Listener {
    /// Only bind while holding the paste lock: it replaces any stale socket.
    pub fn bind() -> std::io::Result<Self> {
        let path = socket_path();
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path)?;
        Ok(Self { socket, path })
    }

    pub fn drain(&self) {
        let _ = self.socket.set_nonblocking(true);
        let mut buf = [0u8; 1];
        while self.socket.recv(&mut buf).is_ok() {}
    }

    pub fn wait(&self, timeout: Duration) -> bool {
        let _ = self.socket.set_nonblocking(false);
        if self.socket.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        let mut buf = [0u8; 1];
        self.socket.recv(&mut buf).is_ok()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// True when a running paste was listening and got the signal.
pub fn notify() -> bool {
    UnixDatagram::unbound()
        .and_then(|socket| socket.send_to(b"r", socket_path()))
        .is_ok()
}

/// Record a synthetic send. A launch that misses the listener but starts
/// shortly after a send still came from it, e.g. modifiers held after the
/// running paste gave up.
pub fn mark_sent() {
    if let Err(e) = std::fs::File::create(sent_path()) {
        log::warn!("recording the paste send failed: {e}");
    }
}

pub fn sent_within(window: Duration) -> bool {
    std::fs::metadata(sent_path())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < window)
}

fn socket_path() -> PathBuf {
    super::runtime_dir().join("secret-stripper-paste.sock")
}

fn sent_path() -> PathBuf {
    super::runtime_dir().join("secret-stripper-paste.sent")
}
