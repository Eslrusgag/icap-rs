//! Demonstrates proxy authentication (RFC 3507 §7.1).
//!
//! When an ICAP server sits behind a proxy that requires credentials, it
//! responds with `407 Proxy Authentication Required` and a
//! `Proxy-Authenticate` challenge header. The client should retry the request
//! once with `Proxy-Authorization: Basic <base64(username:password)>`.
//!
//! Configure credentials via [`ClientBuilder::proxy_auth`]:
//!
//! ```rust,no_run
//! use icap_rs::Client;
//!
//! let client = Client::builder()
//!     .host("proxy.example.com")
//!     .proxy_auth("alice", "hunter2")
//!     .build();
//! ```
//!
//! The retry is transparent — the caller receives the final response (204 on
//! success) without seeing the intermediate 407.
//!
//! The example drives two scenarios against an embedded raw ICAP server:
//!
//! 1. **With credentials** — client retries automatically; server returns 204.
//! 2. **Without credentials** — 407 is returned to the caller as-is.
//!
//! ```text
//! cargo run --example proxy_auth_client
//! ```

use icap_rs::{Client, Request as IcapRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Embedded server
// ---------------------------------------------------------------------------

/// Read bytes from a TCP stream until the first CRLFCRLF.
async fn read_icap_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return (!buf.is_empty()).then_some(buf);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(buf);
        }
    }
}

/// Start a raw ICAP server that:
///
/// - Returns `407` on the *first* REQMOD received on each connection.
/// - Returns `204` on the *second* REQMOD (the authenticated retry).
///
/// Returns `(port, total_requests_seen, last_proxy_auth_value)`.
async fn start_auth_server() -> (u16, Arc<AtomicUsize>, Arc<tokio::sync::Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let total_requests = Arc::new(AtomicUsize::new(0));
    let last_auth = Arc::new(tokio::sync::Mutex::new(String::new()));

    let tr = Arc::clone(&total_requests);
    let la = Arc::clone(&last_auth);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let tr = Arc::clone(&tr);
            let la = Arc::clone(&la);
            tokio::spawn(async move {
                loop {
                    let Some(head) = read_icap_head(&mut stream).await else {
                        return;
                    };
                    let head_str = String::from_utf8_lossy(&head);
                    tr.fetch_add(1, Ordering::SeqCst);

                    // Record the Proxy-Authorization header if present.
                    if let Some(line) = head_str
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
                    {
                        *la.lock().await = line
                            .split_once(':')
                            .map_or("", |(_, value)| value)
                            .trim()
                            .to_string();
                    }

                    // A real proxy checks whether credentials are present and
                    // valid.  We accept any non-empty Proxy-Authorization value.
                    let has_auth = head_str
                        .lines()
                        .any(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"));

                    let resp = if has_auth {
                        "ICAP/1.0 204 No Content\r\n\
                         ISTag: \"auth-ok\"\r\n\
                         Encapsulated: null-body=0\r\n\r\n"
                            .to_string()
                    } else {
                        "ICAP/1.0 407 Proxy Authentication Required\r\n\
                         Proxy-Authenticate: Basic realm=\"icap-proxy\"\r\n\
                         Encapsulated: null-body=0\r\n\r\n"
                            .to_string()
                    };

                    if stream.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    (port, total_requests, last_auth)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (port, total_requests, last_auth) = start_auth_server().await;
    println!("ICAP server listening on 127.0.0.1:{port}");
    println!("Server behaviour: 407 on first request, 204 on retry.\n");

    let null_body_reqmod = IcapRequest::reqmod("/scan").allow_204();

    // -----------------------------------------------------------------------
    // Scenario 1 — With credentials: transparent retry, caller sees 204.
    // -----------------------------------------------------------------------
    println!("=== Scenario 1: client with proxy_auth (\"alice\", \"hunter2\") ===");

    let client_with_auth = Client::builder()
        .host("127.0.0.1")
        .port(port)
        .proxy_auth("alice", "hunter2")
        .build();

    let resp = client_with_auth.send(&null_body_reqmod).await?;

    println!("Final status : {}", resp.status_code());
    println!(
        "Requests sent: {} (1 challenge + 1 authenticated retry)",
        total_requests.load(Ordering::SeqCst)
    );
    println!(
        "Proxy-Authorization sent: {}",
        last_auth.lock().await.as_str()
    );
    // base64("alice:hunter2") == YWxpY2U6aHVudGVyMg==
    println!("Expected     : Basic YWxpY2U6aHVudGVyMg==\n");

    // -----------------------------------------------------------------------
    // Scenario 2 — Without credentials: 407 is returned as-is.
    // -----------------------------------------------------------------------
    println!("=== Scenario 2: client without proxy_auth ===");

    let client_no_auth = Client::builder()
        .host("127.0.0.1")
        .port(port)
        // no .proxy_auth()
        .build();

    let resp = client_no_auth.send(&null_body_reqmod).await?;

    println!("Final status : {}", resp.status_code());
    println!(
        "Requests sent total: {} (no retry — 407 forwarded to caller)",
        total_requests.load(Ordering::SeqCst)
    );

    // -----------------------------------------------------------------------
    // Notes
    // -----------------------------------------------------------------------
    println!("\n--- Notes ---");
    println!("• The retry happens at most once per send() call.");
    println!("• If the retry also yields 407, that response is returned to the caller.");
    println!("• Credentials are encoded as Base64(username:password) per RFC 7617.");

    Ok(())
}
