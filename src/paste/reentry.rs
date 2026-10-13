use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

/// Socket through which a second `paste`, launched while the first one holds
/// the lock, tells the first that its synthetic keys fired the chord again.
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

pub fn notify() {
    if let Ok(socket) = UnixDatagram::unbound() {
        let _ = socket.send_to(b"r", socket_path());
    }
}

fn socket_path() -> PathBuf {
    super::runtime_dir().join("secret-stripper-paste.sock")
}
