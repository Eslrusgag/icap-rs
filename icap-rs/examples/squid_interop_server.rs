//! Squid interoperability ICAP server.
//!
//! Services:
//! - `reqmod`: blocks selected request URLs before Squid contacts the origin.
//! - `respmod`: adds a visible response header to show RESPMOD was applied.
//!
//! The default bind address is `[::]:1344` so Squid running in Docker can reach
//! the service through `host.docker.internal` on Docker Desktop hosts where that
//! name may resolve to an IPv6 address.

use http::{HeaderValue, Request as HttpRequest, Response as HttpResponse, StatusCode, Version};
use icap_rs::{
    Body, EmbeddedHttp, HandlerResult, IncomingRequest, Response, Server, ServiceOptions,
};
use tracing::{info, warn};

const REQMOD_ISTAG: &str = "squid-reqmod-1.0";
const RESPMOD_ISTAG: &str = "squid-respmod-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let bind_addr = std::env::var("ICAP_LISTEN").unwrap_or_else(|_| "[::]:1344".to_string());

    let reqmod_options = ServiceOptions::new()
        .with_static_istag(REQMOD_ISTAG)
        .with_service("icap-rs Squid REQMOD demo")
        .with_options_ttl(60)
        .allow_204()
        .with_preview(0);

    let respmod_options = ServiceOptions::new()
        .with_static_istag(RESPMOD_ISTAG)
        .with_service("icap-rs Squid RESPMOD demo")
        .with_options_ttl(60)
        .allow_204()
        .with_preview(1024);

    let server = Server::builder()
        .bind(&bind_addr)
        // Squid may probe OPTIONS without Encapsulated. Keep this explicit so
        // the interop example accepts that legacy wire shape intentionally.
        .with_compatibility_request_parser()
        .route_reqmod(
            "reqmod",
            |request: IncomingRequest| async move { handle_reqmod(request) },
            Some(reqmod_options),
        )
        .route_respmod(
            "respmod",
            |request: IncomingRequest| async move { handle_respmod(request) },
            Some(respmod_options),
        )
        .build()
        .await?;

    info!(%bind_addr, "Squid interop ICAP server started");
    server.run().await?;
    Ok(())
}

fn handle_reqmod(request: IncomingRequest) -> HandlerResult<Response> {
    let Some(EmbeddedHttp::Req { head, .. }) = request.embedded() else {
        warn!("REQMOD without embedded HTTP request");
        return Ok(Response::no_content_with_istag(REQMOD_ISTAG)?);
    };

    let host = request_host(head);
    let path = head.uri().path().to_ascii_lowercase();
    let reason = block_reason(&host, &path);

    info!(
        method = %head.method(),
        uri = %head.uri(),
        host = %host,
        blocked = reason.is_some(),
        "Squid REQMOD"
    );

    if let Some(reason) = reason {
        return Ok(Response::ok_with_istag(REQMOD_ISTAG)?.with_http_response(&block_page(reason)?)?);
    }

    Ok(Response::no_content_with_istag(REQMOD_ISTAG)?)
}

fn handle_respmod(request: IncomingRequest) -> HandlerResult<Response> {
    let Some(EmbeddedHttp::Resp { head, body }) = request.embedded() else {
        warn!("RESPMOD without embedded HTTP response");
        return Ok(Response::no_content_with_istag(RESPMOD_ISTAG)?);
    };

    info!(
        status = %head.status(),
        body = body_kind(body),
        "Squid RESPMOD"
    );

    let Body::Full { reader } = body else {
        return Ok(Response::no_content_with_istag(RESPMOD_ISTAG)?);
    };

    let mut builder = HttpResponse::builder()
        .status(head.status())
        .version(head.version());

    if let Some(headers) = builder.headers_mut() {
        for (name, value) in head.headers() {
            if name == http::header::TRANSFER_ENCODING {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&reader.len().to_string())?,
        );
        headers.insert("X-ICAP-Respmod", HeaderValue::from_static("icap-rs"));
    }

    let http = builder.body(reader.clone())?;
    Ok(Response::ok_with_istag(RESPMOD_ISTAG)?.with_http_response(&http)?)
}

fn request_host(head: &HttpRequest<()>) -> String {
    if let Some(host) = head.uri().host() {
        return host.to_string();
    }

    head.headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn block_reason(host: &str, path: &str) -> Option<&'static str> {
    if host.eq_ignore_ascii_case("blocked.test") {
        return Some("blocked host");
    }
    if path.contains("blocked") {
        return Some("blocked URL path");
    }
    if path.ends_with(".exe") || path.ends_with(".zip") {
        return Some("blocked file extension");
    }
    None
}

fn block_page(reason: &'static str) -> HandlerResult<HttpResponse<Vec<u8>>> {
    let html = format!(
        "<!doctype html><html><body><h1>Blocked by icap-rs</h1><p>{reason}</p></body></html>"
    );

    Ok(HttpResponse::builder()
        .status(StatusCode::FORBIDDEN)
        .version(Version::HTTP_11)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("X-ICAP-Reqmod", "icap-rs")
        .header("X-Block-Reason", reason)
        .header(http::header::CONTENT_LENGTH, html.len().to_string())
        .body(html.into_bytes())?)
}

fn body_kind(body: &Body<Vec<u8>>) -> &'static str {
    match body {
        Body::Full { .. } => "full",
        Body::Preview { .. } => "preview",
        Body::Empty => "empty",
    }
}
