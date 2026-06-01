//! RESPMOD: header-only modification of the upstream HTTP response.
//!
//! Demonstrates how to return a modified response when only the headers change:
//! - strips `Set-Cookie` (privacy)
//! - strips `Server` and `X-Powered-By` (fingerprint reduction)
//! - injects `X-Filtered-By: icap-rs`
//! - forces `Cache-Control: no-store` on text/html
//!
//! When no header change is needed the service returns 204 No Content so the
//! proxy reuses the original upstream response without copying bytes.

use http::{Response as HttpResponse, header};
use icap_rs::request::{Body, EmbeddedHttp, IncomingRequest};
use icap_rs::response::Response;
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tracing::info;

const ISTAG: &str = "modify-headers-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let opts = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Header Sanitizer")
        .allow_204()
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_respmod(
            "sanitize",
            move |req: IncomingRequest| async move {
                let Some(EmbeddedHttp::Resp { head, body, .. }) = req.embedded() else {
                    return Ok(Response::no_content_with_istag(ISTAG)?);
                };

                let strip = head.headers().contains_key(header::SET_COOKIE)
                    || head.headers().contains_key("server")
                    || head.headers().contains_key("x-powered-by");
                let is_html = head
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|s| s.to_ascii_lowercase().starts_with("text/html"));

                if !strip && !is_html {
                    info!("no changes -> 204");
                    return Ok(Response::no_content_with_istag(ISTAG)?);
                }

                // Re-emit headers minus the stripped ones; reuse the original body bytes.
                let body_bytes: Vec<u8> = match body {
                    Body::Full { reader } => reader.clone(),
                    _ => Vec::new(),
                };

                let mut builder = HttpResponse::builder()
                    .status(head.status())
                    .version(head.version());
                if let Some(h) = builder.headers_mut() {
                    for (name, value) in head.headers() {
                        let n = name.as_str();
                        if n.eq_ignore_ascii_case("set-cookie")
                            || n.eq_ignore_ascii_case("server")
                            || n.eq_ignore_ascii_case("x-powered-by")
                            || n.eq_ignore_ascii_case("transfer-encoding")
                        {
                            continue;
                        }
                        h.append(name.clone(), value.clone());
                    }
                    h.insert(
                        header::CONTENT_LENGTH,
                        body_bytes.len().to_string().parse().unwrap(),
                    );
                    h.insert("X-Filtered-By", "icap-rs".parse().unwrap());
                    if is_html {
                        h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                    }
                }
                let http = builder.body(body_bytes).map_err(|e| {
                    icap_rs::HandlerError::internal(format!("build http::Response: {e}"))
                })?;

                info!(stripped = %strip, html = %is_html, "modified headers");
                Ok(Response::ok_with_istag(ISTAG)?.with_http_response(&http)?)
            },
            Some(opts),
        )
        .build()
        .await?;

    info!("listening on 127.0.0.1:1344 (service: sanitize)");
    server.run().await?;
    Ok(())
}
