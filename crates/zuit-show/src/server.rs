//! `tiny_http` server bootstrap for `zuit-show`. See spec §7 / §8.

use crate::history::HistoryStore;
use crate::router;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use tiny_http::Server;

/// Handle for a running HTTP server.
///
/// Call [`stop`](Self::stop) (or simply drop this value) to shut it down.
pub struct ServerHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Kept alive so the worker's `recv_timeout` loop drains cleanly on drop.
    _server: Arc<Server>,
}

impl ServerHandle {
    /// The address the server is bound to (host + OS-assigned port).
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Signal shutdown and join the worker thread.
    ///
    /// `tiny_http` does not expose an unblock primitive; setting the flag and
    /// waiting for the 100 ms `recv_timeout` poll to notice is the simplest
    /// approach that avoids unsafe code.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Bind to `addr` and spawn a background worker thread.
///
/// Pass `"127.0.0.1:0"` for `addr` to let the OS pick a free port; read
/// [`ServerHandle::addr`] after `start` returns to discover the bound port.
///
/// # Panics
///
/// Panics if the TCP `Server::http` bind somehow returns a Unix-socket address
/// (invariant: `tiny_http::Server::http` always produces a TCP `ListenAddr`).
///
/// # Errors
///
/// Returns `Err` if the bind fails (port in use, permission denied, etc.).
pub fn start(
    addr: &str,
    store: Arc<HistoryStore>,
    version: String,
) -> Result<ServerHandle, std::io::Error> {
    let server = Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
    let server = Arc::new(server);
    let actual = server
        .server_addr()
        .to_ip()
        .expect("invariant: tiny_http::Server::http always binds a TCP address");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown2 = shutdown.clone();
    let svr = server.clone();

    let join = thread::Builder::new()
        .name("zuit-show-http".to_string())
        .spawn(move || {
            let timeout = std::time::Duration::from_millis(100);
            while !shutdown2.load(Ordering::SeqCst) {
                match svr.recv_timeout(timeout) {
                    Ok(Some(req)) => router::handle(&store, req, &version),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(ServerHandle {
        addr: actual,
        shutdown,
        join: Some(join),
        _server: server,
    })
}

/// Bind using an already-open `TcpListener` and spawn a background worker thread.
///
/// This is the race-free alternative to [`start`]: the caller binds the listener,
/// reads `local_addr().port()`, writes `daemon.json`, and then hands the live
/// listener here.  `tiny_http`'s `Server::from_listener` takes ownership of the
/// socket so the port is never released between steps.
///
/// # Errors
///
/// Returns `Err` if the server cannot be constructed from the listener or if the
/// background thread cannot be spawned.
pub fn start_with_listener(
    listener: TcpListener,
    store: Arc<HistoryStore>,
    version: String,
) -> Result<ServerHandle, std::io::Error> {
    let actual = listener
        .local_addr()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let server =
        Server::from_listener(listener, None).map_err(|e| std::io::Error::other(e.to_string()))?;
    let server = Arc::new(server);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown2 = shutdown.clone();
    let svr = server.clone();

    let join = thread::Builder::new()
        .name("zuit-show-http".to_string())
        .spawn(move || {
            let timeout = std::time::Duration::from_millis(100);
            while !shutdown2.load(Ordering::SeqCst) {
                match svr.recv_timeout(timeout) {
                    Ok(Some(req)) => router::handle(&store, req, &version),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(ServerHandle {
        addr: actual,
        shutdown,
        join: Some(join),
        _server: server,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn server_start_and_healthz_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(HistoryStore::open(tmp.path()));
        let handle = start("127.0.0.1:0", store, "0.1.0".to_string()).unwrap();
        let url = format!("http://{}/api/healthz", handle.addr());
        let body = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(2))
            .call()
            .unwrap()
            .into_string()
            .unwrap();
        let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(resp["ok"], true);
        handle.stop();
    }

    #[test]
    fn server_start_with_listener_and_healthz_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(HistoryStore::open(tmp.path()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = start_with_listener(listener, store, "0.2.0".to_string()).unwrap();
        let url = format!("http://{}/api/healthz", handle.addr());
        let body = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(2))
            .call()
            .unwrap()
            .into_string()
            .unwrap();
        let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(resp["ok"], true);
        handle.stop();
    }
}
