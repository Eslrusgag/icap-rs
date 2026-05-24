//! REQMOD: routing decisions based on ICAP-level headers.
//!
//! Demonstrates inspecting ICAP request headers such as `X-Client-IP` and
//! `X-Authenticated-User` (commonly injected by Squid / c-icap) and choosing
//! one of three outcomes:
//!   * allow  -> 204 No Content (no modification)
//!   * audit  -> 204 with an extra `X-Audit` ICAP header for the proxy log
//!   * block  -> 200 with an embedded HTTP 403 page
//!
//! Try it with rs-icap-client, e.g.:
//!   rs-icap-client -i 127.0.0.1 -p 1344 -s reqmod \
//!       --icap-header 'X-Client-IP: 10.0.0.5' \
//!       --icap-header 'X-Authenticated-User: alice' \
//!       --url 'http://example.com/'

use http::{HeaderMap, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::request::IncomingRequest;
use icap_rs::response::Response;
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tracing::info;

const ISTAG: &str = "route-icap-hdr-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let opts = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Routing by ICAP header")
        .allow_204()
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "reqmod",
            move |req: IncomingRequest| async move {
                let client_ip = icap_header(req.icap_headers(), "X-Client-IP");
                let user = icap_header(req.icap_headers(), "X-Authenticated-User");
                info!(?client_ip, ?user, "REQMOD");

                match decide(&client_ip, &user) {
                    Decision::Allow => Ok(Response::no_content_with_istag(ISTAG)?),
                    Decision::Audit(tag) => Ok(Response::no_content_with_istag(ISTAG)?
                        .add_header("X-Audit", tag)),
                    Decision::Block(reason) => {
                        let html = format!(
                            "<h1>Blocked</h1><p>{reason}</p>"
                        );
                        let http = HttpResponse::builder()
                            .status(HttpStatus::FORBIDDEN)
                            .version(Version::HTTP_11)
                            .header("Content-Type", "text/html; charset=utf-8")
                            .header("Content-Length", html.len().to_string())
                            .header("X-Block-Reason", reason)
                            .body(html.into_bytes())
                            .unwrap();
                        Response::ok_with_istag(ISTAG)?.with_http_response(&http)
                    }
                }
            },
            Some(opts),
        )
        .build()
        .await?;

    info!("listening on 127.0.0.1:1344 (service: reqmod)");
    server.run().await?;
    Ok(())
}

enum Decision {
    Allow,
    Audit(&'static str),
    Block(&'static str),
}

fn decide(client_ip: &Option<String>, user: &Option<String>) -> Decision {
    // Toy policy:
    // - unauthenticated requests are blocked outright
    // - a known bad subnet is blocked
    // - the "guests" user is allowed but audited
    // - everyone else passes through unchanged
    let Some(user) = user.as_deref() else {
        return Decision::Block("authentication required");
    };
    if let Some(ip) = client_ip.as_deref()
        && ip.starts_with("10.6.6.")
    {
        return Decision::Block("source subnet on denylist");
    }
    if user.eq_ignore_ascii_case("guests") {
        return Decision::Audit("guest-traffic");
    }
    Decision::Allow
}

fn icap_header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
