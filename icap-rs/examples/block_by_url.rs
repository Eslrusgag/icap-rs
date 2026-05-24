//! REQMOD: block requests by URL extension or by host denylist.
//!
//! - GET .../*.exe, *.zip, *.iso  -> HTTP 403 page
//! - Host in DENY_HOSTS           -> HTTP 403 page
//! - otherwise                    -> 204 No Content

use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::request::{EmbeddedHttp, IncomingRequest};
use icap_rs::response::Response;
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tracing::info;

const ISTAG: &str = "block-url-1.0";
const BLOCKED_EXT: &[&str] = &[".exe", ".zip", ".iso", ".dmg"];
const DENY_HOSTS: &[&str] = &["malware.test", "ads.example.com"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let opts = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("URL Blocker")
        .allow_204()
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "block",
            move |req: IncomingRequest| async move {
                let Some(EmbeddedHttp::Req { head, .. }) = req.embedded() else {
                    return Ok(Response::no_content_with_istag(ISTAG)?);
                };

                let uri = head.uri();
                let host = uri.host().unwrap_or_else(|| {
                    head.headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                });
                let path = uri.path().to_ascii_lowercase();

                if let Some(reason) = should_block(host, &path) {
                    info!(%host, %path, %reason, "BLOCK");
                    let http = block_page(reason);
                    return Response::ok_with_istag(ISTAG)?.with_http_response(&http);
                }

                Ok(Response::no_content_with_istag(ISTAG)?)
            },
            Some(opts),
        )
        .build()
        .await?;

    info!("listening on 127.0.0.1:1344 (service: block)");
    server.run().await?;
    Ok(())
}

fn should_block(host: &str, path: &str) -> Option<&'static str> {
    if DENY_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h)) {
        return Some("host on denylist");
    }
    if BLOCKED_EXT.iter().any(|ext| path.ends_with(ext)) {
        return Some("file extension not allowed");
    }
    None
}

fn block_page(reason: &'static str) -> HttpResponse<Vec<u8>> {
    let html = format!("<h1>Blocked</h1><p>{reason}</p>");
    HttpResponse::builder()
        .status(HttpStatus::FORBIDDEN)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Content-Length", html.len().to_string())
        .header("X-Block-Reason", reason)
        .body(html.into_bytes())
        .unwrap()
}
