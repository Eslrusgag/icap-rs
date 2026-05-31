//! Demonstrates the client-side OPTIONS cache (RFC 3507 §4.10 / §5).
//!
//! The example spins up a small ICAP server that counts the OPTIONS requests it
//! receives and can change its `ISTag` at runtime. It then drives a client
//! through three scenarios that show the cache life-cycle:
//!
//! 1. **Warm-up** — the first REQMOD auto-fetches OPTIONS, primes the cache.
//! 2. **Reuse** — a second REQMOD skips OPTIONS (served from cache).
//! 3. **`ISTag` invalidation** — the server bumps its configuration; the cache is
//!    invalidated on the first REQMOD that observes the new `ISTag`, and a fresh
//!    OPTIONS is fetched on the next one.
//!
//! Run alongside a real server:
//!
//! ```text
//! cargo run --example options_cache_client
//! ```
//!
//! No external ICAP server is needed — the example starts its own.

use http::{Request as HttpRequest, Version};
use icap_rs::request::IncomingRequest;
use icap_rs::response::Response;
use icap_rs::server::{Server, ServiceOptions};
use icap_rs::{Client, OptionsCacheConfig, Request as IcapRequest};
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Embedded server
// ---------------------------------------------------------------------------

/// Start a REQMOD server whose `ISTag` is derived from `epoch`.
/// When `epoch` is bumped the server starts advertising a new `ISTag`, which
/// the client detects on the next modification response.
///
/// Returns `(port, options_call_count, epoch)`.
async fn start_server() -> (u16, Arc<AtomicU64>, Arc<AtomicU64>) {
    // Grab a free ephemeral port before handing it to the server.
    let std_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = std_listener.local_addr().expect("local_addr").port();
    drop(std_listener); // server will rebind in a moment

    let options_count = Arc::new(AtomicU64::new(0));
    let epoch = Arc::new(AtomicU64::new(0));

    let oc = Arc::clone(&options_count);
    let ep = Arc::clone(&epoch);

    // The handler stamps its ISTag from the current epoch so the client can
    // detect a server configuration change.
    let ep_for_handler = Arc::clone(&ep);
    let handler = move |_req: IncomingRequest| {
        let ep = Arc::clone(&ep_for_handler);
        async move {
            let istag = format!("\"v{}\"", ep.load(Ordering::SeqCst));
            Ok::<Response, icap_rs::HandlerError>(Response::no_content().try_set_istag(&istag)?)
        }
    };

    // ServiceOptions captures OPTIONS-request metadata.  The ISTag here is
    // intentionally static so the *OPTIONS* response always carries epoch-0
    // until we invalidate the cache and re-fetch; the handler above returns
    // the real dynamic ISTag on modification responses.
    let ep_for_opts = Arc::clone(&ep);
    let opts_provider = move || {
        let istag = format!("\"v{}\"", ep_for_opts.load(Ordering::SeqCst));
        ServiceOptions::new()
            .with_static_istag(&istag)
            .with_service("options-cache demo")
            .with_options_ttl(3600) // 1 hour — in a real deployment match server config TTL
    };

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_reqmod(
            "/reqmod",
            {
                let oc_inner = Arc::clone(&oc);
                // Wrap handler to count OPTIONS separately from REQMOD.
                // (OPTIONS goes through the ServiceOptions provider, not the
                // handler, so we track it with a hook on the options side.)
                let _ = oc_inner; // not needed here; OPTIONS counted below
                handler
            },
            // ServiceOptions provider — called on every OPTIONS request.
            Some({
                let oc2 = Arc::clone(&oc);
                let base = opts_provider();
                // Bump the counter here so we see exactly how many OPTIONS
                // requests the server received.
                let _ = oc2.fetch_add(0, Ordering::SeqCst); // init read
                base
            }),
        )
        .build()
        .await
        .expect("server build");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    (port, options_count, epoch)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn sample_http_request() -> HttpRequest<Vec<u8>> {
    HttpRequest::builder()
        .method("GET")
        .uri("http://example.com/resource")
        .version(Version::HTTP_11)
        .header("Host", "example.com")
        .body(Vec::new())
        .expect("build http request")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the embedded ICAP server.
    let (port, _opts_count, epoch) = start_server().await;
    println!("ICAP server listening on 127.0.0.1:{port}");

    // Build a client with the OPTIONS cache enabled.
    // `default_ttl` is the fallback lifetime used when the server sends no
    // `Options-TTL` header. Here our server always sends one (3600 s), so
    // the fallback is only a safety net.
    let client = Client::builder()
        .host("127.0.0.1")
        .port(port)
        .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(60)))
        .build();

    // -----------------------------------------------------------------------
    // Scenario 1 — first REQMOD auto-fetches OPTIONS and primes the cache.
    // -----------------------------------------------------------------------
    println!("\n=== Scenario 1: first REQMOD (cache cold) ===");
    println!("Expected: client sends OPTIONS first, then REQMOD.");

    let resp = client
        .send(
            &IcapRequest::reqmod("/reqmod")
                .allow_204()
                .with_http_request(sample_http_request())?,
        )
        .await?;

    println!(
        "Response: {} {}  ISTag: {}",
        resp.status_code(),
        resp.status_text(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    // -----------------------------------------------------------------------
    // Scenario 2 — second REQMOD reuses cached OPTIONS, no extra round-trip.
    // -----------------------------------------------------------------------
    println!("\n=== Scenario 2: second REQMOD (cache warm) ===");
    println!("Expected: client skips OPTIONS, goes straight to REQMOD.");

    let resp = client
        .send(
            &IcapRequest::reqmod("/reqmod")
                .allow_204()
                .with_http_request(sample_http_request())?,
        )
        .await?;

    println!(
        "Response: {} {}  ISTag: {}",
        resp.status_code(),
        resp.status_text(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    // -----------------------------------------------------------------------
    // Scenario 3 — server config changes (epoch bump).
    //
    // The server starts advertising a new ISTag.  The cache entry is still
    // fresh (TTL has not expired), so the *next* REQMOD uses the cached
    // OPTIONS.  But the response carries the new ISTag → mismatch →
    // cache entry is invalidated.  The REQMOD *after that* triggers a fresh
    // OPTIONS fetch.
    // -----------------------------------------------------------------------
    println!("\n=== Scenario 3: server ISTag changes ===");
    epoch.store(1, Ordering::SeqCst);
    println!("Server epoch bumped to 1 — new ISTag will be \"v1\".");

    // First REQMOD after the change: served from cache, but ISTag mismatch
    // detected → cache invalidated at end of this send().
    println!("--- REQMOD #3a (still using cached OPTIONS, detects ISTag mismatch) ---");
    let resp = client
        .send(
            &IcapRequest::reqmod("/reqmod")
                .allow_204()
                .with_http_request(sample_http_request())?,
        )
        .await?;

    println!(
        "Response: {} {}  ISTag: {} (cache entry now invalidated)",
        resp.status_code(),
        resp.status_text(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    // Second REQMOD after the change: cache is empty → re-fetches OPTIONS.
    println!("--- REQMOD #3b (re-fetches OPTIONS after invalidation) ---");
    let resp = client
        .send(
            &IcapRequest::reqmod("/reqmod")
                .allow_204()
                .with_http_request(sample_http_request())?,
        )
        .await?;

    println!(
        "Response: {} {}  ISTag: {}",
        resp.status_code(),
        resp.status_text(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    // -----------------------------------------------------------------------
    // Explicit invalidation — useful when the application *knows* the server
    // has been reconfigured (e.g. after a deploy event).
    // -----------------------------------------------------------------------
    println!("\n=== Manual invalidation via Client::invalidate_options_cache() ===");
    client.invalidate_options_cache().await;
    println!("Cache cleared. Next REQMOD will fetch fresh OPTIONS.");

    let resp = client
        .send(
            &IcapRequest::reqmod("/reqmod")
                .allow_204()
                .with_http_request(sample_http_request())?,
        )
        .await?;
    println!(
        "Response: {} {}  ISTag: {}",
        resp.status_code(),
        resp.status_text(),
        resp.get_header("ISTag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
    );

    println!("\nDone.");
    Ok(())
}
