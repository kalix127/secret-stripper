use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
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
        Self::bind_at(socket_path())
    }

    fn bind_at(path: PathBuf) -> std::io::Result<Self> {
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
    notify_at(&socket_path())
}

fn notify_at(path: &Path) -> bool {
    UnixDatagram::unbound()
        .and_then(|socket| socket.send_to(b"r", path))
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

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(50);

    fn socket_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("paste.sock")
    }

    #[test]
    fn notify_without_a_listener_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!notify_at(&socket_in(&dir)));
    }

    #[test]
    fn listener_receives_one_signal_per_notify() {
        let dir = tempfile::TempDir::new().unwrap();
        let listener = Listener::bind_at(socket_in(&dir)).unwrap();
        assert!(!listener.wait(SHORT));
        assert!(notify_at(&socket_in(&dir)));
        assert!(listener.wait(SHORT));
        assert!(!listener.wait(SHORT));
    }

    #[test]
    fn drain_drops_pending_signals() {
        let dir = tempfile::TempDir::new().unwrap();
        let listener = Listener::bind_at(socket_in(&dir)).unwrap();
        assert!(notify_at(&socket_in(&dir)));
        assert!(notify_at(&socket_in(&dir)));
        listener.drain();
        assert!(!listener.wait(SHORT));
    }

    #[test]
    fn bind_replaces_a_stale_socket_and_drop_removes_it() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(socket_in(&dir), "stale").unwrap();
        let listener = Listener::bind_at(socket_in(&dir)).unwrap();
        assert!(notify_at(&socket_in(&dir)));
        drop(listener);
        assert!(!socket_in(&dir).exists());
        assert!(!notify_at(&socket_in(&dir)));
    }
}
