// Minimal ICAP server with several services:
// - reqmod:    demonstrates REQMOD flow and 204 handling
// - respmod:   demonstrates RESPMOD flow and 204 handling
// - blocker:   returns ICAP 200 with an encapsulated HTTP 403 "Blocked!" page (for REQMOD & RESPMOD)

use std::sync::{Arc, RwLock};

use http::{HeaderMap, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::request::{EmbeddedHttp, Request};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{Body, Method};
use tracing::{error, info, warn};

const ISTAG_REQMOD_INIT: &str = "reqmod-1.0";
const ISTAG_RESPMOD_INIT: &str = "respmod-1.0";
const ISTAG_BLOCKER_INIT: &str = "blocker-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Shared, mutable ISTag sources per service
    let req_tag = Arc::new(RwLock::new(String::from(ISTAG_REQMOD_INIT)));
    let resp_tag = Arc::new(RwLock::new(String::from(ISTAG_RESPMOD_INIT)));
    let block_tag = Arc::new(RwLock::new(String::from(ISTAG_BLOCKER_INIT)));

    // OPTIONS configs using dynamic ISTag providers
    let reqmod_opts = ServiceOptions::new()
        .with_istag_provider({
            let t = Arc::clone(&req_tag);
            move |_req: &Request| t.read().unwrap().clone()
        })
        .with_service("Request Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(1024);

    let respmod_opts = ServiceOptions::new()
        .with_istag_provider({
            let t = Arc::clone(&resp_tag);
            move |_req: &Request| t.read().unwrap().clone()
        })
        .with_service("Response Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(2048);

    // Blocker: announce BOTH methods in OPTIONS (methods будут проставлены роутером)
    let blocker_opts = ServiceOptions::new()
        .with_istag_provider({
            let t = Arc::clone(&block_tag);
            move |_req: &Request| t.read().unwrap().clone()
        })
        .with_service("Request/Response Blocker")
        .with_options_ttl(3600)
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // ---------- REQMOD demo ----------
        .route_reqmod(
            "reqmod",
            {
                let t = Arc::clone(&req_tag);
                move |request: Request| {
                    let t = Arc::clone(&t);
                    async move {
                        info!("REQMOD called: {}", request.service);

                        if let Some(EmbeddedHttp::Req { head, .. }) = &request.embedded {
                            info!("HTTP {} {}", head.method(), head.uri());
                        } else {
                            warn!("REQMOD without embedded HTTP request");
                        }

                        let istag_now = t.read().unwrap().clone();

                        if can_return_204(&request.icap_headers) {
                            return Ok(Response::no_content()
                                .try_set_istag(&istag_now)?
                                .add_header("Server", "icap-rs/0.1.0"));
                        }

                        Ok(Response::no_content()
                            .try_set_istag(&istag_now)?
                            .add_header("Server", "icap-rs/0.1.0"))
                    }
                }
            },
            Some(reqmod_opts),
        )
        // ---------- RESPMOD demo ----------
        .route_respmod(
            "respmod",
            {
                let t = Arc::clone(&resp_tag);
                move |request: Request| {
                    let t = Arc::clone(&t);
                    async move {
                        info!("RESPMOD called: {}", request.service);

                        if let Some(EmbeddedHttp::Resp { head, .. }) = &request.embedded {
                            info!("HTTP status: {}", head.status());
                        } else {
                            warn!("RESPMOD without embedded HTTP response");
                        }

                        let istag_now = t.read().unwrap().clone();

                        if request.preview_size.is_some() && can_return_204(&request.icap_headers) {
                            return Ok(Response::no_content()
                                .try_set_istag(&istag_now)?
                                .add_header("Server", "icap-rs/0.1.0"));
                        }

                        if let Some(EmbeddedHttp::Resp {
                            head,
                            body: Body::Full { reader },
                        }) = &request.embedded
                        {
                            let mut builder = http::Response::builder()
                                .status(head.status())
                                .version(head.version());
                            if let Some(h) = builder.headers_mut() {
                                h.extend(head.headers().clone());
                                h.remove(http::header::TRANSFER_ENCODING);
                                h.insert(
                                    http::header::CONTENT_LENGTH,
                                    http::HeaderValue::from_str(&reader.len().to_string()).unwrap(),
                                );
                            }
                            let http_resp = builder
                                .body(reader.clone())
                                .map_err(|e| format!("build http::Response: {e}"))?;

                            return Ok(Response::new(StatusCode::OK, "OK")
                                .try_set_istag(&istag_now)?
                                .with_http_response(&http_resp)?
                                .add_header("Server", "icap-rs/0.1.0"));
                        }
                        Ok(Response::no_content()
                            .try_set_istag(&istag_now)?
                            .add_header("Server", "icap-rs/0.1.0"))
                    }
                }
            },
            Some(respmod_opts),
        )
        // ---------- Blocker (REQMOD & RESPMOD) ----------
        .route(
            "blocker",
            [Method::ReqMod, Method::RespMod],
            {
                let t = Arc::clone(&block_tag);
                move |request: Request| {
                    let t = Arc::clone(&t);
                    async move {
                        if request.method == Method::ReqMod {
                            if let Some(EmbeddedHttp::Req { head, .. }) = &request.embedded {
                                info!("BLOCKER REQMOD for {} {}", head.method(), head.uri());
                            } else {
                                warn!("BLOCKER: REQMOD without embedded HTTP request");
                            }
                        } else if request.method == Method::RespMod {
                            if let Some(EmbeddedHttp::Resp { head, .. }) = &request.embedded {
                                info!("BLOCKER RESPMOD, upstream status {}", head.status());
                            } else {
                                warn!("BLOCKER: RESPMOD without embedded HTTP response");
                            }
                        }

                        let istag_now = t.read().unwrap().clone();
                        let http = build_block_403_http("Blocked!", &istag_now);
                        Response::new(StatusCode::OK, "OK")
                            .try_set_istag(&istag_now)?
                            .with_http_response(&http)
                    }
                }
            },
            Some(blocker_opts),
        )
        .build()
        .await?;

    info!("ICAP server started on 127.0.0.1:1344 (services: reqmod, respmod, blocker)");
    if let Err(e) = server.run().await {
        error!("server error: {e}");
        return Err(e.into());
    }
    Ok(())
}

fn can_return_204(h: &HeaderMap) -> bool {
    h.get("Allow")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p.trim().eq_ignore_ascii_case("204")))
        .unwrap_or(false)
}

/// Build a simple HTTP 403 page with a reason (as http::Response<Vec<u8>>).
fn build_block_403_http(reason: &str, istag: &str) -> HttpResponse<Vec<u8>> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Blocked</title>
</head>
<body>
  <h1>Blocked!</h1>
  <p>{}</p>
</body>
</html>"#,
        reason
    );

    HttpResponse::builder()
        .status(HttpStatus::FORBIDDEN)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .header("X-ICAP-Blocked", istag)
        .header("X-Block-Reason", reason)
        .header("Content-Length", html.len().to_string())
        .body(html.into_bytes())
        .unwrap()
}
