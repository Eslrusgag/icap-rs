// Minimal ICAP server with several services:
// - reqmod:    demonstrates REQMOD flow and 204 handling
// - respmod:   demonstrates RESPMOD flow and 204 handling
// - blocker:   returns ICAP 200 with an encapsulated HTTP 403 "Blocked!" page (for REQMOD & RESPMOD)

use http::{HeaderMap, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::Method;
use icap_rs::options::OptionsConfig;
use icap_rs::request::{EmbeddedHttp, Request};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use tracing::{error, info, warn};

const ISTAG_REQMOD: &str = "reqmod-1.0";
const ISTAG_RESPMOD: &str = "respmod-1.0";
const ISTAG_BLOCKER: &str = "blocker-1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // OPTIONS configs (SmallVec-based)
    let reqmod_opts = OptionsConfig::new(ISTAG_REQMOD)
        .with_service("Request Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(1024);

    let respmod_opts = OptionsConfig::new(ISTAG_RESPMOD)
        .with_service("Response Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(2048);

    // Blocker: announce BOTH methods in OPTIONS
    let blocker_opts = OptionsConfig::new(ISTAG_BLOCKER)
        .with_service("Request/Response Blocker")
        .with_options_ttl(3600)
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // ---------- REQMOD demo ----------
        .route_reqmod("reqmod", |request: Request| async move {
            info!("REQMOD called: {}", request.service);

            if let Some(EmbeddedHttp::Req(http_req)) = &request.embedded {
                info!("HTTP {} {}", http_req.method(), http_req.uri());
            } else {
                warn!("REQMOD without embedded HTTP request");
            }

            if can_return_204(&request.icap_headers) {
                return Ok(Response::no_content()
                    .try_set_istag(ISTAG_REQMOD)?
                    .add_header("Server", "icap-rs/0.1.0"));
            }

            Ok(Response::no_content()
                .try_set_istag(ISTAG_REQMOD)?
                .add_header("Server", "icap-rs/0.1.0"))
        })
        .set_options("reqmod", reqmod_opts)
        // ---------- RESPMOD demo ----------
        .route_respmod("respmod", |request: Request| async move {
            info!("RESPMOD called: {}", request.service);

            if let Some(EmbeddedHttp::Resp(http_resp)) = &request.embedded {
                info!("HTTP status: {}", http_resp.status());
            } else {
                warn!("RESPMOD without embedded HTTP response");
            }

            if can_return_204(&request.icap_headers) {
                return Ok(Response::no_content()
                    .try_set_istag(ISTAG_RESPMOD)?
                    .add_header("Server", "icap-rs/0.1.0"));
            }

            if let Some(EmbeddedHttp::Resp(http_resp)) = &request.embedded {
                return Ok(Response::new(StatusCode::Ok200, "OK")
                    .try_set_istag(ISTAG_RESPMOD)?
                    .with_http_response(http_resp)?
                    .add_header("Server", "icap-rs/0.1.0"));
            }

            Ok(Response::no_content()
                .try_set_istag(ISTAG_RESPMOD)?
                .add_header("Server", "icap-rs/0.1.0"))
        })
        .set_options("respmod", respmod_opts)
        // ---------- Blocker (REQMOD & RESPMOD) ----------
        .route(
            "blocker",
            [Method::ReqMod, Method::RespMod],
            |request: Request| async move {
                if request.method == Method::ReqMod {
                    if let Some(EmbeddedHttp::Req(http_req)) = &request.embedded {
                        info!(
                            "BLOCKER REQMOD for {} {}",
                            http_req.method(),
                            http_req.uri()
                        );
                    } else {
                        warn!("BLOCKER: REQMOD without embedded HTTP request");
                    }
                } else if request.method == Method::RespMod {
                    if let Some(EmbeddedHttp::Resp(http_resp)) = &request.embedded {
                        info!("BLOCKER RESPMOD, upstream status {}", http_resp.status());
                    } else {
                        warn!("BLOCKER: RESPMOD without embedded HTTP response");
                    }
                }

                let http = build_block_403_http("Blocked!");
                Ok(Response::new(StatusCode::Ok200, "OK")
                    .try_set_istag(ISTAG_BLOCKER)?
                    .with_http_response(&http)?)
            },
        )
        .set_options("blocker", blocker_opts)
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
        .map(|s| s.split(',').any(|p| p.trim() == "204"))
        .unwrap_or(false)
}

/// Build a simple HTTP 403 page with a reason (as http::Response<Vec<u8>>).
fn build_block_403_http(reason: &str) -> HttpResponse<Vec<u8>> {
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
        .header("X-ICAP-Blocked", ISTAG_BLOCKER)
        .header("X-Block-Reason", reason)
        .header("Content-Length", html.len().to_string())
        .body(html.into_bytes())
        .unwrap()
}
