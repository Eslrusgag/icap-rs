//! Shared helpers for integration tests.
//!
//! Files under `tests/common/` are not compiled as standalone test binaries by
//! Cargo, so this module can be re-imported via `mod common;` from each test
//! file without producing a duplicate test target.

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

/// Bind to port 0 and return the OS-assigned ephemeral port.
///
/// Using ephemeral ports avoids collisions when tests run in parallel and
/// removes the need to hand out fixed port ranges across files.
pub fn find_free_port() -> u16 {
    let sock = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    sock.local_addr().expect("local addr").port()
}

/// Poll `addr` with TCP connects until the server starts accepting, or fail.
///
/// Replaces the legacy "sleep 50ms and hope" pattern: returns as soon as the
/// listener is ready, and panics with a clear message if it never comes up.
pub async fn wait_port_ready(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("server did not start listening on {addr}");
}
