//! RESPMOD: inject a response header without buffering the body (`Allow: 206`).
//!
//! Many ICAP deployments only need to add or remove HTTP response headers — the
//! body itself does not have to be inspected or copied.  This example shows how
//! to do that efficiently using the `206 Partial Content` / `use-original-body`
//! flow (RFC 3507 §4.7):
//!
//! 1. The client advertises `Allow: 206`.
//! 2. The service modifies the HTTP response head (adds `X-Scanned-By`) and
//!    returns `206 Partial Content` with `use-original-body=0`.
//! 3. The proxy reassembles the modified head with the original body it already
//!    has — no body bytes travel over the ICAP connection at all.
//!
//! When the client does not advertise `Allow: 206` the service returns
//! `204 No Content` (no modification) or echoes the adapted response as a
//! regular `200 OK`, depending on whether `Allow: 204` is present.
//!
//! Run the server:
//!
//! ```bash
//! cargo run -p icap-rs --example partial_content_respmod
//! ```
//!
//! Then send a request with the CLI (requires a running server):
//!
//! ```bash
//! cargo run -p rs-icap-client -- \
//!     -u icap://127.0.0.1:1344/stamp \
//!     -m RESPMOD \
//!     --allow-206 \
//!     -v
//! ```

use http::{Response as HttpResponse, header};
use icap_rs::request::{EmbeddedHttp, IncomingRequest};
use icap_rs::response::Response;
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tracing::info;

const ISTAG: &str = "stamp-headers-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let opts = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Header Stamper (206)")
        .allow_204()
        .allow_206();

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_respmod(
            "stamp",
            move |req: IncomingRequest| async move {
                let allow_206 = req
                    .icap_headers()
                    .get("Allow")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|s| {
                        s.split(',').any(|t| t.trim().eq_ignore_ascii_case("206"))
                    });

                // Log the originating HTTP request URI when the client includes it
                // (RFC 3507 §4.4.1 req-hdr section).
                if let Some(embedded) = req.embedded() {
                    if let Some(orig_req) = embedded.respmod_request_head() {
                        info!(uri = %orig_req.uri(), "originating HTTP request");
                    }
                }

                let Some(EmbeddedHttp::Resp { head, .. }) = req.into_embedded() else {
                    return Ok(Response::no_content_with_istag(ISTAG)?);
                };

                if allow_206 {
                    // Build a modified HTTP response head — body stays with the proxy.
                    let (mut parts, ()) = head.into_parts();
                    parts.headers.remove(header::TRANSFER_ENCODING);
                    parts
                        .headers
                        .insert("X-Scanned-By", "icap-rs".parse().unwrap());

                    let modified_head = HttpResponse::from_parts(parts, ());

                    info!("stamped header, returning 206 use-original-body");
                    return Ok(Response::partial_content_with_istag(ISTAG)?
                        .with_http_response_head_and_original_body(&modified_head, 0)?);
                }

                // Client did not advertise Allow: 206 — fall back to 204 (no modification).
                // The proxy reuses its cached copy of the response unchanged.
                info!("Allow: 206 absent, returning 204");
                Ok(Response::no_content_with_istag(ISTAG)?)
            },
            Some(opts),
        )
        .build()
        .await?;

    info!("listening on icap://127.0.0.1:1344/stamp");
    server.run().await?;
    Ok(())
}
