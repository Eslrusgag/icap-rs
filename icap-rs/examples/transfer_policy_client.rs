//! Demonstrates client-side Transfer-* policy consumption (RFC 3507 §4.10.2).
//!
//! When the OPTIONS cache is enabled, the client reads the server's
//! `Transfer-Preview`, `Transfer-Ignore`, and `Transfer-Complete` headers and
//! automatically applies the matching policy to each REQMOD request:
//!
//! | Header            | Effect                                                  |
//! |-------------------|---------------------------------------------------------|
//! | `Transfer-Ignore` | Client returns a synthetic 204 — server is not contacted|
//! | `Transfer-Preview`| Client sends the first N bytes and waits for 100 Continue|
//! | `Transfer-Complete`| Client sends the full body without a `Preview` header  |
//!
//! Priority (highest first): Complete > Ignore > Preview. `*` matches all types.
//!
//! The example drives four scenarios against an embedded raw ICAP server that
//! records what it receives:
//!
//! 1. `.jpg`  → Transfer-Ignore  → synthetic 204, server not reached.
//! 2. `.html` → Transfer-Preview → server receives `Preview: 512`.
//! 3. `.gif`  → Transfer-Complete → server receives no `Preview` header.
//! 4. `.js`   → no policy match  → request uses its own preview settings.
//!
//! ```text
//! cargo run --example transfer_policy_client
//! ```

use http::{Request as HttpRequest, Version};
use icap_rs::{Client, OptionsCacheConfig, Request as IcapRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Embedded server
// ---------------------------------------------------------------------------

/// Read bytes from a TCP stream until the first CRLFCRLF (end of ICAP headers).
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

/// Start a raw ICAP server that advertises the following Transfer-* policy:
///
/// ```text
/// Transfer-Ignore:   jpg, png
/// Transfer-Preview:  html, css
/// Transfer-Complete: gif
/// Preview: 512
/// ```
///
/// Returns `(port, reqmod_count)`.
/// `reqmod_count` is incremented for every REQMOD that actually reaches the
/// server — Transfer-Ignore requests never arrive.
async fn start_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let reqmod_count = Arc::new(AtomicUsize::new(0));

    let rc = Arc::clone(&reqmod_count);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let rc = Arc::clone(&rc);
            tokio::spawn(async move {
                loop {
                    let Some(head) = read_icap_head(&mut stream).await else {
                        return;
                    };
                    let head_str = String::from_utf8_lossy(&head);

                    let resp = if head_str.starts_with("OPTIONS") {
                        // Advertise the Transfer-* policy.
                        "ICAP/1.0 200 OK\r\n\
                         ISTag: \"transfer-demo\"\r\n\
                         Options-TTL: 3600\r\n\
                         Methods: REQMOD\r\n\
                         Transfer-Ignore: jpg, png\r\n\
                         Transfer-Preview: html, css\r\n\
                         Transfer-Complete: gif\r\n\
                         Preview: 512\r\n\
                         Encapsulated: null-body=0\r\n\r\n"
                            .to_string()
                    } else {
                        // REQMOD reached the server — record it.
                        rc.fetch_add(1, Ordering::SeqCst);

                        // Echo the Preview header value (or "none") so the
                        // example can print what the server actually observed.
                        let preview = head_str
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("preview:"))
                            .and_then(|l| l.splitn(2, ':').nth(1))
                            .map(|v| v.trim().to_string())
                            .unwrap_or_else(|| "none".to_string());

                        format!(
                            "ICAP/1.0 204 No Content\r\n\
                             ISTag: \"transfer-demo\"\r\n\
                             X-Preview-Seen: {preview}\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                        )
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
    (port, reqmod_count)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn reqmod_for(uri: &str) -> IcapRequest {
    let http_req = HttpRequest::builder()
        .method("GET")
        .uri(uri)
        .version(Version::HTTP_11)
        .header("Host", "example.com")
        .body(Vec::new())
        .expect("build http request");
    IcapRequest::reqmod("/reqmod")
        .allow_204()
        .with_http_request(http_req)
        .expect("build reqmod")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (port, reqmod_count) = start_server().await;
    println!("ICAP server listening on 127.0.0.1:{port}");
    println!(
        "Policy: Transfer-Ignore: jpg,png  Transfer-Preview: html,css  Transfer-Complete: gif  Preview: 512\n"
    );

    let client = Client::builder()
        .host("127.0.0.1")
        .port(port)
        // Enable the OPTIONS cache — required for Transfer-* policy to apply.
        .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(60)))
        .build();

    // -----------------------------------------------------------------------
    // Scenario 1 — Transfer-Ignore: server is bypassed entirely.
    // -----------------------------------------------------------------------
    println!("=== Scenario 1: GET /photo.jpg (Transfer-Ignore) ===");
    let resp = client
        .send(&reqmod_for("http://example.com/photo.jpg"))
        .await?;
    println!(
        "Status: {}  ISTag: {}",
        resp.status_code(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );
    println!(
        "REQMODs received by server: {} (expected 0 — bypassed)\n",
        reqmod_count.load(Ordering::SeqCst)
    );

    // -----------------------------------------------------------------------
    // Scenario 2 — Transfer-Preview: server sees Preview: 512.
    // -----------------------------------------------------------------------
    println!("=== Scenario 2: GET /index.html (Transfer-Preview) ===");
    let resp = client
        .send(&reqmod_for("http://example.com/index.html"))
        .await?;
    println!(
        "Status: {}  Preview header seen by server: {}",
        resp.status_code(),
        resp.get_header("X-Preview-Seen")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );
    println!(
        "REQMODs received by server: {} (expected 1)\n",
        reqmod_count.load(Ordering::SeqCst)
    );

    // -----------------------------------------------------------------------
    // Scenario 3 — Transfer-Complete: server sees no Preview header.
    // -----------------------------------------------------------------------
    println!("=== Scenario 3: GET /icon.gif (Transfer-Complete) ===");
    let resp = client
        .send(&reqmod_for("http://example.com/icon.gif"))
        .await?;
    println!(
        "Status: {}  Preview header seen by server: {}",
        resp.status_code(),
        resp.get_header("X-Preview-Seen")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );
    println!(
        "REQMODs received by server: {} (expected 2)\n",
        reqmod_count.load(Ordering::SeqCst)
    );

    // -----------------------------------------------------------------------
    // Scenario 4 — No matching policy: request uses its own settings.
    // -----------------------------------------------------------------------
    println!("=== Scenario 4: GET /app.js (no Transfer-* policy) ===");
    let resp = client
        .send(&reqmod_for("http://example.com/app.js"))
        .await?;
    println!(
        "Status: {}  Preview header seen by server: {}",
        resp.status_code(),
        resp.get_header("X-Preview-Seen")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );
    println!(
        "REQMODs received by server: {} (expected 3)\n",
        reqmod_count.load(Ordering::SeqCst)
    );

    println!("Done.");
    Ok(())
}
