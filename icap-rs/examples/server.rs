// Minimal ICAP server with several services:
// - reqmod:    demonstrates REQMOD flow and 204 handling
// - respmod:   demonstrates RESPMOD flow and 204 handling
// - blocker:   returns ICAP 200 with an encapsulated HTTP 403 "Blocked!" page

use http::HeaderMap;
use icap_rs::options::{IcapMethod, OptionsConfig};
use icap_rs::request::{EmbeddedHttp, Request};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let reqmod_opts = OptionsConfig::new(vec![IcapMethod::ReqMod], "reqmod-1.0")
        .with_service("Request Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(1024);

    let respmod_opts = OptionsConfig::new(vec![IcapMethod::RespMod], "respmod-1.0")
        .with_service("Response Modifier")
        .with_options_ttl(3600)
        .add_allow("204")
        .with_preview(2048);

    // New service: always returns ICAP 200 with encapsulated HTTP 403 "Blocked!"
    let blocker_opts = OptionsConfig::new(vec![IcapMethod::ReqMod], "blocker-1.0")
        .with_service("Request Blocker")
        .with_options_ttl(3600)
        .with_preview(0);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .with_max_connections(1)
        // reqmod: if client allows 204 and no changes required, return 204
        .add_service("reqmod", |request: Request| async move {
            info!("REQMOD called: {}", request.service);

            if !request.method.eq_ignore_ascii_case("REQMOD") {
                return Ok(
                    Response::new(StatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0"),
                );
            }

            if let Some(EmbeddedHttp::Req(http_req)) = &request.embedded {
                info!("HTTP {} {}", http_req.method(), http_req.uri());
            } else {
                warn!("REQMOD without embedded HTTP request");
            }

            if can_return_204(&request.icap_headers) {
                return Ok(Response::no_content().add_header("Server", "icap-rs/0.1.0"));
            }

            Ok(Response::new(StatusCode::Ok200, "OK")
                .add_header("Content-Length", "0")
                .add_header("Server", "icap-rs/0.1.0"))
        })
        .add_options_config("reqmod", reqmod_opts)
        // respmod: demonstrate access to embedded HTTP response
        .add_service("respmod", |request: Request| async move {
            info!("RESPMOD called: {}", request.service);

            if !request.method.eq_ignore_ascii_case("RESPMOD") {
                return Ok(
                    Response::new(StatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0"),
                );
            }

            if let Some(EmbeddedHttp::Resp(http_resp)) = &request.embedded {
                info!("HTTP status: {}", http_resp.status());
            } else {
                warn!("RESPMOD without embedded HTTP response");
            }

            if can_return_204(&request.icap_headers) {
                return Ok(Response::no_content().add_header("Server", "icap-rs/0.1.0"));
            }

            Ok(Response::new(StatusCode::Ok200, "OK")
                .add_header("Content-Length", "0")
                .add_header("Server", "icap-rs/0.1.0"))
        })
        .add_options_config("respmod", respmod_opts)
        // blocker: return ICAP 200 with encapsulated HTTP 403 "Blocked!"
        .add_service("blocker", |request: Request| async move {
            info!("BLOCKER (REQMOD): {}", request.service);

            if !request.method.eq_ignore_ascii_case("REQMOD") {
                return Ok(
                    Response::new(StatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0"),
                );
            }

            if let Some(EmbeddedHttp::Req(http_req)) = &request.embedded {
                info!("BLOCKER saw HTTP {} {}", http_req.method(), http_req.uri());
            } else {
                warn!("BLOCKER: REQMOD without embedded HTTP request");
            }

            // Build a block page (encapsulated HTTP response)
            let reason = "Blocked!";
            let body = create_block_403(reason);

            // Encapsulated: res-hdr=0, res-body=<offset of the HTTP body>
            let (hdr_len, _) = split_http_bytes(&body);

            Ok(Response::new(StatusCode::Ok200, "OK")
                .add_header("ISTag", "\"blocker-1.0\"")
                .add_header("Encapsulated", &format!("res-hdr=0, res-body={}", hdr_len))
                .with_body(&body))
        })
        .add_options_config("blocker", blocker_opts)
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

/// Returns (HTTP-headers length, HTTP-body length) for raw HTTP bytes.
fn split_http_bytes(raw: &[u8]) -> (usize, usize) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        let hdr_len = pos + 4;
        let body_len = raw.len().saturating_sub(hdr_len);
        (hdr_len, body_len)
    } else {
        (raw.len(), 0)
    }
}

/// Build a simple HTTP 403 page with a reason.
fn create_block_403(reason: &str) -> Vec<u8> {
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

    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache, no-store, must-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         X-ICAP-Blocked: blocker-1.0\r\n\
         X-Block-Reason: {}\r\n\
         \r\n\
         {}",
        html.len(),
        reason,
        html
    );
    resp.into_bytes()
}
