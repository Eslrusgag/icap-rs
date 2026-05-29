//! RFC 3507 integration conformance matrix.
//!
//! The test names intentionally encode the support status and the supported
//! variation. `supported_*` tests are release assertions. `unsupported_*`
//! tests are ignored placeholders for visible RFC gaps that should not be
//! mistaken for implemented behavior.

use http::{Request as HttpRequest, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::HandlerResult;
use icap_rs::request::{IncomingRequest, Request};
use icap_rs::response::{ParsedResponse, Response, StatusCode};
use icap_rs::server::options::{ServiceOptions, TransferBehavior};
use icap_rs::server::{PreviewDecision, Server};
use icap_rs::{Client, Method, OptionsCacheConfig};
use std::net::TcpListener as StdTcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

const ISTAG: &str = "rfc3507";

async fn no_modification_handler(_req: IncomingRequest) -> HandlerResult<Response> {
    Ok(Response::no_content().try_set_istag(ISTAG)?)
}

async fn preview_final_handler(_req: IncomingRequest) -> HandlerResult<PreviewDecision> {
    Ok(PreviewDecision::Respond(
        Response::no_content().try_set_istag(ISTAG)?,
    ))
}

fn unused_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

async fn start_respmod_server() -> u16 {
    let port = unused_port();
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_respmod(
            "respmod",
            no_modification_handler,
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("RFC 3507 RESPMOD")
                    .with_options_ttl(60)
                    .add_allow("204")
                    .add_allow("206")
                    .with_preview(1024),
            ),
        )
        .default_service("respmod")
        .build()
        .await
        .expect("build respmod server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn start_preview_server() -> u16 {
    let port = unused_port();
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_reqmod(
            "scan",
            preview_final_handler,
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("RFC 3507 Preview")
                    .with_preview(4)
                    .add_allow("204"),
            ),
        )
        .build()
        .await
        .expect("build preview server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn start_compatibility_options_server() -> u16 {
    let port = unused_port();
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .with_compatibility_request_parser()
        .route_respmod(
            "respmod",
            no_modification_handler,
            Some(ServiceOptions::new().with_static_istag(ISTAG)),
        )
        .build()
        .await
        .expect("build compatibility server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn start_options_capability_server() -> u16 {
    let port = unused_port();
    let options = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("RFC 3507 service")
        .with_options_ttl(60)
        .with_service_id("rfc3507-service")
        .add_allow("204")
        .add_allow("206")
        .with_preview(1024)
        .add_transfer_rule("txt", TransferBehavior::Preview)
        .add_transfer_rule("zip", TransferBehavior::Ignore)
        .with_default_transfer_behavior(TransferBehavior::Complete);
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route(
            "scan",
            [Method::ReqMod, Method::RespMod],
            no_modification_handler,
            Some(options),
        )
        .build()
        .await
        .expect("build options capability server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn send_raw_icap_request(port: u16, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write raw request");
    stream.shutdown().await.expect("shutdown write");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    raw
}

fn find_double_crlf(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .expect("CRLFCRLF")
}

fn first_line(bytes: &[u8]) -> &str {
    let line_end = bytes
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("line end");
    std::str::from_utf8(&bytes[..line_end]).expect("utf8 status line")
}

fn embedded_http_response(body: &str) -> HttpResponse<Vec<u8>> {
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/plain")
        .header("Content-Length", body.len().to_string())
        .body(body.as_bytes().to_vec())
        .expect("http response")
}

mod section_4_3_messages {
    use super::*;

    #[test]
    fn supported_options_request_wire_is_icap_1_0_with_host_and_null_body() {
        let client = Client::builder().host("icap.example").port(1344).build();
        let wire = client
            .get_request(&Request::options("respmod"))
            .expect("serialize options");
        let text = String::from_utf8(wire).expect("utf8 request");

        assert!(text.starts_with("OPTIONS icap://icap.example:1344/respmod ICAP/1.0\r\n"));
        assert!(text.contains("\r\nHost: icap.example\r\n"));
        assert!(text.contains("\r\nEncapsulated: null-body=0\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn supported_server_maps_malformed_requests_to_icap_errors() {
        let port = start_respmod_server().await;

        let bad_version = send_raw_icap_request(
            port,
            &format!(
                "REQMOD icap://127.0.0.1:{port}/respmod ICAP/2.0\r\n\
                 Host: 127.0.0.1:{port}\r\n\
                 Encapsulated: null-body=0\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(first_line(&bad_version), "ICAP/1.0 400 Bad Request");

        let unknown_method = send_raw_icap_request(
            port,
            &format!(
                "FOO icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
                 Host: 127.0.0.1:{port}\r\n\
                 Encapsulated: null-body=0\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(first_line(&unknown_method), "ICAP/1.0 501 Not Implemented");

        let missing_host = send_raw_icap_request(
            port,
            &format!(
                "REQMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
                 Encapsulated: null-body=0\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(first_line(&missing_host), "ICAP/1.0 400 Bad Request");

        let invalid_encapsulated = send_raw_icap_request(
            port,
            &format!(
                "REQMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
                 Host: 127.0.0.1:{port}\r\n\
                 Encapsulated: req-hdr=10, req-body=5\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(
            first_line(&invalid_encapsulated),
            "ICAP/1.0 400 Bad Request"
        );
    }
}

mod section_4_4_encapsulated {
    use super::*;

    #[test]
    fn supported_reqmod_wire_keeps_http_head_unchunked_and_chunks_entity_body() {
        let client = Client::builder().host("icap.example").port(1344).build();
        let http = HttpRequest::builder()
            .method("POST")
            .uri("http://origin.example/upload")
            .version(Version::HTTP_11)
            .header("Host", "origin.example")
            .header("Content-Length", "5")
            .body(b"hello".to_vec())
            .expect("http request");
        let wire = client
            .get_request(
                &Request::reqmod("scan")
                    .with_http_request(http)
                    .expect("build reqmod request"),
            )
            .expect("serialize reqmod");
        let icap_header_end = find_double_crlf(&wire);
        let encapsulated = std::str::from_utf8(&wire[..icap_header_end]).expect("icap head");

        assert!(encapsulated.contains("Encapsulated: req-hdr=0, req-body="));
        assert_eq!(&wire[icap_header_end..icap_header_end + 5], b"POST ");
        assert!(wire.ends_with(b"\r\n5\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn supported_response_wire_keeps_http_head_unchunked_and_chunks_entity_body() {
        let raw = Response::new(StatusCode::OK, "OK")
            .try_set_istag(ISTAG)
            .expect("istag")
            .with_http_response(&embedded_http_response("hello"))
            .expect("embedded http")
            .to_raw()
            .expect("serialize response");
        let icap_header_end = find_double_crlf(&raw);
        let text = String::from_utf8_lossy(&raw);

        assert_eq!(&raw[icap_header_end..icap_header_end + 5], b"HTTP/");
        assert!(text.contains("Encapsulated: res-hdr=0, res-body="));
        assert!(text.ends_with("\r\n5\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn supported_response_parser_returns_dechunked_encapsulated_area() {
        let parsed = ParsedResponse::from_raw(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: rfc3507\r\n\
              Encapsulated: res-hdr=0, res-body=38\r\n\
              \r\n\
              HTTP/1.1 200 OK\r\n\
              Content-Length: 5\r\n\
              \r\n\
              5\r\n\
              hello\r\n\
              0\r\n\
              \r\n",
        )
        .expect("parse response");

        assert_eq!(
            parsed.body(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn supported_client_reads_rfc_response_with_unchunked_http_head_and_chunked_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = socket.read(&mut tmp).await.expect("read request");
                assert!(n > 0, "client closed before sending request");
                request.extend_from_slice(&tmp[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            socket
                .write_all(
                    b"ICAP/1.0 200 OK\r\n\
                      ISTag: rfc3507\r\n\
                      Encapsulated: res-hdr=0, res-body=38\r\n\
                      \r\n\
                      HTTP/1.1 200 OK\r\n\
                      Content-Length: 5\r\n\
                      \r\n\
                      5\r\n\
                      hello\r\n\
                      0\r\n\
                      \r\n",
                )
                .await
                .expect("write response");
        });

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let response = client
            .send(&Request::options("svc"))
            .await
            .expect("send options");

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(
            response.body(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
    }
}

mod section_4_5_preview {
    use super::*;

    #[tokio::test]
    async fn supported_preview_handler_can_send_final_response_before_100_continue() {
        let port = start_preview_server().await;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let http_head = b"POST http://origin.example/upload HTTP/1.1\r\n\
                          Host: origin.example\r\n\
                          Content-Length: 9\r\n\
                          \r\n";
        let req_body_offset = http_head.len();
        let icap_head = format!(
            "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: req-hdr=0, req-body={req_body_offset}\r\n\
             Preview: 4\r\n\
             Allow: 204\r\n\
             \r\n"
        );
        stream
            .write_all(icap_head.as_bytes())
            .await
            .expect("write icap head");
        stream.write_all(http_head).await.expect("write http head");
        stream
            .write_all(b"4\r\nping\r\n0\r\n\r\n")
            .await
            .expect("write preview");

        let mut response = vec![0; 1024];
        let n = stream.read(&mut response).await.expect("read response");
        let line = first_line(&response[..n]);

        assert_eq!(line, "ICAP/1.0 204 No Content");
    }

    // RFC 3507 §4.5: `Preview` header value MUST be a non-negative integer.
    // Malformed values are a protocol error and the server must reject the
    // request with `400 Bad Request` rather than silently treating it as
    // "no preview".
    #[tokio::test]
    async fn supported_malformed_preview_header_is_rejected_with_400() {
        let port = start_preview_server().await;

        for bad in ["abc", "-1", " ", "12a", ""] {
            let raw = send_raw_icap_request(
                port,
                &format!(
                    "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
                     Host: 127.0.0.1:{port}\r\n\
                     Encapsulated: req-hdr=0, null-body=0\r\n\
                     Preview: {bad}\r\n\
                     \r\n"
                ),
            )
            .await;
            assert_eq!(
                first_line(&raw),
                "ICAP/1.0 400 Bad Request",
                "Preview: {bad:?} should be rejected"
            );
        }
    }

    // RFC 3507 §4.5: `Preview: 0` is a valid value meaning "advertise preview
    // capability without prefetching body bytes". It must be accepted.
    #[tokio::test]
    async fn supported_preview_zero_is_accepted() {
        let port = start_preview_server().await;
        let raw = send_raw_icap_request(
            port,
            &format!(
                "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
                 Host: 127.0.0.1:{port}\r\n\
                 Encapsulated: req-hdr=0, null-body=0\r\n\
                 Preview: 0\r\n\
                 Allow: 204\r\n\
                 \r\n"
            ),
        )
        .await;
        let line = first_line(&raw);
        assert!(
            line.starts_with("ICAP/1.0 2"),
            "Preview: 0 must yield a 2xx response, got: {line}"
        );
    }
}

mod sections_4_6_and_4_7_responses {
    use super::*;

    #[tokio::test]
    async fn supported_204_requires_allow_or_preview_otherwise_server_returns_200() {
        let port = start_respmod_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let no_allow = client
            .send(
                &Request::respmod("respmod")
                    .with_http_response(embedded_http_response("hello"))
                    .expect("build respmod request"),
            )
            .await
            .expect("send without allow");
        assert_eq!(no_allow.status_code(), StatusCode::OK);

        let allow_204 = client
            .send(
                &Request::respmod("respmod")
                    .allow_204()
                    .with_http_response(embedded_http_response("hello"))
                    .expect("build respmod request"),
            )
            .await
            .expect("send allow 204");
        assert_eq!(allow_204.status_code(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn supported_206_uses_original_body_marker_for_no_modification() {
        let port = start_respmod_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let response = client
            .send(
                &Request::respmod("respmod")
                    .allow_206()
                    .with_http_response(embedded_http_response("hello"))
                    .expect("build respmod request"),
            )
            .await
            .expect("send allow 206");

        assert_eq!(response.status_code(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.use_original_body_offset(), Some(0));
        assert!(!String::from_utf8_lossy(response.body()).contains("hello"));
    }

    #[test]
    fn supported_success_responses_require_istag() {
        let err = ParsedResponse::from_raw(b"ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n")
            .expect_err("2xx without ISTag must fail");

        assert!(err.to_string().contains("ISTag"));
    }

    #[test]
    fn supported_response_parser_rejects_invalid_rfc_shapes() {
        let wrong_version = ParsedResponse::from_raw(
            b"ICAP/2.0 200 OK\r\n\
              ISTag: rfc3507\r\n\
              Encapsulated: null-body=0\r\n\
              \r\n",
        )
        .expect_err("ICAP/2.0 must fail");
        assert!(wrong_version.to_string().contains("ICAP/2.0"));

        let duplicate_encapsulated = ParsedResponse::from_raw(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: rfc3507\r\n\
              Encapsulated: res-hdr=0, res-body=100\r\n\
              Encapsulated: req-hdr=0\r\n\
              \r\n",
        )
        .expect_err("duplicate Encapsulated must fail");
        assert!(
            duplicate_encapsulated
                .to_string()
                .to_lowercase()
                .contains("encapsulated")
        );

        let invalid_204 = ParsedResponse::from_raw(
            b"ICAP/1.0 204 No Content\r\n\
              ISTag: rfc3507\r\n\
              Encapsulated: res-hdr=0\r\n\
              \r\n",
        )
        .expect_err("204 must use null-body");
        assert!(invalid_204.to_string().contains("null-body=0"));
    }

    #[test]
    fn supported_istag_validation_cases() {
        let valid = ParsedResponse::from_raw(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: ok-Tag.123\r\n\
              Encapsulated: null-body=0\r\n\
              \r\n",
        )
        .expect("valid ISTag");
        assert_eq!(valid.get_header("ISTag").expect("ISTag"), "ok-Tag.123");

        let invalid = ParsedResponse::from_raw(
            b"ICAP/1.0 200 OK\r\n\
              ISTag: BAD TAG\r\n\
              Encapsulated: null-body=0\r\n\
              \r\n",
        )
        .expect_err("invalid ISTag");
        assert!(invalid.to_string().to_lowercase().contains("istag"));
    }
}

mod section_4_10_options {
    use super::*;

    #[tokio::test]
    async fn supported_service_options_advertise_rfc_capabilities() {
        let port = start_options_capability_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();
        let response = client
            .send(&Request::options("scan"))
            .await
            .expect("send options");

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(
            response.get_header("Methods").expect("Methods"),
            "REQMOD, RESPMOD"
        );
        assert_eq!(response.get_header("ISTag").expect("ISTag"), "\"rfc3507\"");
        assert_eq!(
            response.get_header("Encapsulated").expect("Encapsulated"),
            "null-body=0"
        );
        assert_eq!(response.get_header("Allow").expect("Allow"), "204, 206");
        assert_eq!(response.get_header("Preview").expect("Preview"), "1024");
        assert_eq!(
            response
                .get_header("Transfer-Preview")
                .expect("Transfer-Preview"),
            "txt"
        );
        assert_eq!(
            response
                .get_header("Transfer-Ignore")
                .expect("Transfer-Ignore"),
            "zip"
        );
        assert_eq!(
            response
                .get_header("Transfer-Complete")
                .expect("Transfer-Complete"),
            "*"
        );
    }

    #[tokio::test]
    async fn supported_strict_options_requires_encapsulated_but_compatibility_mode_allows_legacy() {
        let strict_port = start_respmod_server().await;
        let strict = send_raw_icap_request(
            strict_port,
            &format!(
                "OPTIONS icap://127.0.0.1:{strict_port}/respmod ICAP/1.0\r\n\
                 Host: 127.0.0.1:{strict_port}\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(first_line(&strict), "ICAP/1.0 400 Bad Request");

        let compatibility_port = start_compatibility_options_server().await;
        let compatibility = send_raw_icap_request(
            compatibility_port,
            &format!(
                "OPTIONS icap://127.0.0.1:{compatibility_port}/respmod ICAP/1.0\r\n\
                 Host: 127.0.0.1:{compatibility_port}\r\n\
                 \r\n"
            ),
        )
        .await;
        assert_eq!(first_line(&compatibility), "ICAP/1.0 200 OK");
    }
}

mod unsupported_rfc3507_gaps {
    #[test]
    #[ignore = "not supported: RFC 3507 Upgrade header TLS handshake; direct icaps:// TLS is supported instead"]
    fn unsupported_section_7_2_upgrade_tls_handshake() {}

    #[test]
    #[ignore = "not supported as first-class API: RFC 3507 proxy/service authentication"]
    fn unsupported_section_7_1_builtin_authentication() {}

    #[test]
    #[ignore = "partial support only: server advertises Transfer-* but client does not automatically apply transfer policy"]
    fn unsupported_section_4_10_2_automatic_transfer_policy_consumption() {}
}

// ---------------------------------------------------------------------------
// RFC 3507 §6.3 — Chunk trailers
// ---------------------------------------------------------------------------
//
// RFC 3507 §6.3 states that ICAP bodies use HTTP/1.1 chunked framing, which
// allows trailer headers after the zero chunk (per RFC 7230 §4.1.2).
// These tests verify that:
//   1. Servers can receive ICAP requests that carry chunk trailers.
//   2. Clients can receive ICAP responses that carry chunk trailers.
//   3. Trailers are exposed through the structured API.

mod section_6_3_chunk_trailers {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // Helper: spin up a minimal REQMOD server whose handler exposes received
    // chunk trailers via a `oneshot` channel.
    async fn start_trailer_capture_server(
        trailer_tx: tokio::sync::oneshot::Sender<http::HeaderMap>,
    ) -> u16 {
        let port = unused_port();
        let trailer_tx = std::sync::Mutex::new(Some(trailer_tx));

        let handler = move |req: IncomingRequest| {
            let tx = trailer_tx.lock().unwrap().take();
            async move {
                if let Some(tx) = tx {
                    let _ = tx.send(req.chunk_trailers().clone());
                }
                Ok::<Response, icap_rs::HandlerError>(Response::no_content().try_set_istag(ISTAG)?)
            }
        };

        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .route_reqmod(
                "svc",
                handler,
                Some(
                    ServiceOptions::new()
                        .with_static_istag(ISTAG)
                        .with_service("Trailer test"),
                ),
            )
            .build()
            .await
            .expect("build server");

        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    /// RFC 3507 §6.3 — server correctly parses chunk trailers sent by a client.
    ///
    /// Sends a hand-crafted ICAP REQMOD request whose chunked HTTP body ends
    /// with a trailer header (`X-Checksum: abc123`).
    #[tokio::test]
    async fn rfc6_3_server_receives_chunk_trailers() {
        let (tx, rx) = tokio::sync::oneshot::channel::<http::HeaderMap>();
        let port = start_trailer_capture_server(tx).await;

        // Build the embedded HTTP request head (unchunked).
        let http_req_head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Chunked body: one data chunk + zero chunk + trailer + empty line.
        let http_body_chunked = b"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n";

        let req_body_offset = http_req_head.len();
        let encapsulated = format!("req-hdr=0, req-body={req_body_offset}");

        // Must advertise Allow: 204 so the server routes to the handler rather
        // than short-circuiting with a 200 echo response.
        let icap_headers = format!(
            "REQMOD icap://127.0.0.1:{port}/svc ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Allow: 204\r\n\
             Encapsulated: {encapsulated}\r\n\
             \r\n"
        );

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        stream
            .write_all(icap_headers.as_bytes())
            .await
            .expect("write headers");
        stream
            .write_all(http_req_head)
            .await
            .expect("write http head");
        stream
            .write_all(http_body_chunked)
            .await
            .expect("write chunked body");
        stream.flush().await.expect("flush");

        // Read and discard the 204 response (handler returned no-content).
        let mut buf = vec![0u8; 4096];
        let _n = stream.read(&mut buf).await.expect("read response");

        // Verify that the server received and parsed the trailer.
        let trailers = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("trailer channel timeout")
            .expect("trailer channel recv");

        let checksum = trailers
            .get("x-checksum")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            checksum, "abc123",
            "X-Checksum trailer must be present and equal abc123"
        );
    }

    /// RFC 3507 §6.3 — server handles requests with no chunk trailers normally.
    ///
    /// Confirms the common case (no trailers) still works correctly and that
    /// `chunk_trailers()` returns an empty map.
    #[tokio::test]
    async fn rfc6_3_server_handles_no_chunk_trailers() {
        let (tx, rx) = tokio::sync::oneshot::channel::<http::HeaderMap>();
        let port = start_trailer_capture_server(tx).await;

        // Chunked body with no trailers (standard terminator).
        let http_req_head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let http_body_chunked = b"5\r\nhello\r\n0\r\n\r\n";

        let req_body_offset = http_req_head.len();
        let encapsulated = format!("req-hdr=0, req-body={req_body_offset}");
        // Must advertise Allow: 204 so the server routes to the handler.
        let icap_headers = format!(
            "REQMOD icap://127.0.0.1:{port}/svc ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Allow: 204\r\n\
             Encapsulated: {encapsulated}\r\n\
             \r\n"
        );

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        stream
            .write_all(icap_headers.as_bytes())
            .await
            .expect("write headers");
        stream
            .write_all(http_req_head)
            .await
            .expect("write http head");
        stream
            .write_all(http_body_chunked)
            .await
            .expect("write chunked body");
        stream.flush().await.expect("flush");

        let mut buf = vec![0u8; 4096];
        let _n = stream.read(&mut buf).await.expect("read response");

        let trailers = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .expect("recv");
        assert!(
            trailers.is_empty(),
            "chunk_trailers() must be empty when no trailers are present"
        );
    }

    /// RFC 3507 §6.3 — client receives and parses chunk trailers in ICAP response.
    ///
    /// A fake ICAP server sends a 200 OK response whose embedded HTTP response
    /// body terminates with a `X-Integrity: sha256=deadbeef` trailer.
    /// The client must expose it via `ParsedResponse::chunk_trailers()`.
    #[tokio::test]
    async fn rfc6_3_client_receives_chunk_trailers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        // Spawn a fake server that sends one response with a chunk trailer.
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            // Drain the incoming request.
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;

            // Build the embedded HTTP response.
            let http_resp_head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
            let http_body_chunked = b"5\r\nhello\r\n0\r\nX-Integrity: sha256=deadbeef\r\n\r\n";

            let res_hdr_offset = 0usize;
            let res_body_offset = http_resp_head.len();
            let enc = format!("res-hdr={res_hdr_offset}, res-body={res_body_offset}");
            let body_bytes: Vec<u8> =
                [http_resp_head.as_ref(), http_body_chunked.as_ref()].concat();
            let icap_resp = format!(
                "ICAP/1.0 200 OK\r\n\
                 ISTag: \"rfc3507\"\r\n\
                 Encapsulated: {enc}\r\n\
                 \r\n"
            );

            sock.write_all(icap_resp.as_bytes())
                .await
                .expect("write resp head");
            sock.write_all(&body_bytes).await.expect("write resp body");
            sock.flush().await.expect("flush");
        });

        tokio::time::sleep(Duration::from_millis(30)).await;

        // Minimal raw ICAP request for OPTIONS to elicit a response.
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        let req = format!(
            "REQMOD icap://127.0.0.1:{port}/svc ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");

        let mut raw = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).await.expect("read");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&tmp[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") && raw.ends_with(b"\r\n") {
                break;
            }
        }

        let parsed = ParsedResponse::from_raw(&raw).expect("parse response");
        let integrity = parsed
            .chunk_trailers()
            .get("x-integrity")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            integrity, "sha256=deadbeef",
            "X-Integrity trailer must be present in client-parsed response"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 3507 §6.4 — Service identity is the full request-URI path
// ---------------------------------------------------------------------------
//
// RFC 3507 §6.4 identifies an ICAP service by its request URI. Two services
// that differ only in a leading path segment (`/a/scan` vs `/b/scan`) are
// distinct services, exactly like distinct HTTP resources. These tests verify
// that the server routes by the full normalized path, not by the final path
// segment, so the shared trailing segment (`scan`) does not collapse them.

mod section_6_4_service_uri_routing {
    use super::*;

    fn embedded_http_get() -> HttpRequest<Vec<u8>> {
        HttpRequest::builder()
            .method("GET")
            .uri("http://origin.example/")
            .version(Version::HTTP_11)
            .header("Host", "origin.example")
            .body(Vec::new())
            .expect("http request")
    }

    // Two REQMOD services that share the final path segment `scan` but live at
    // different full paths. Each handler stamps a distinct ISTag so the caller
    // can tell which route handled the request.
    async fn start_full_path_routing_server() -> u16 {
        let port = unused_port();
        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .route_reqmod(
                "/a/scan",
                |_req: IncomingRequest| async {
                    Ok::<Response, icap_rs::HandlerError>(
                        Response::no_content().try_set_istag("svc-a")?,
                    )
                },
                Some(
                    ServiceOptions::new()
                        .with_static_istag("svc-a")
                        .with_service("Service A"),
                ),
            )
            .route_reqmod(
                "/b/scan",
                |_req: IncomingRequest| async {
                    Ok::<Response, icap_rs::HandlerError>(
                        Response::no_content().try_set_istag("svc-b")?,
                    )
                },
                Some(
                    ServiceOptions::new()
                        .with_static_istag("svc-b")
                        .with_service("Service B"),
                ),
            )
            .build()
            .await
            .expect("build full-path routing server");

        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    /// RFC 3507 §6.4 — REQMOD requests to `/a/scan` and `/b/scan` reach distinct
    /// services even though they share the final path segment `scan`.
    #[tokio::test]
    async fn rfc6_4_routes_by_full_path_not_last_segment() {
        let port = start_full_path_routing_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let resp_a = client
            .send(
                &Request::reqmod("/a/scan")
                    .allow_204()
                    .with_http_request(embedded_http_get())
                    .expect("build reqmod /a/scan"),
            )
            .await
            .expect("send /a/scan");
        let resp_b = client
            .send(
                &Request::reqmod("/b/scan")
                    .allow_204()
                    .with_http_request(embedded_http_get())
                    .expect("build reqmod /b/scan"),
            )
            .await
            .expect("send /b/scan");

        assert_eq!(resp_a.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(resp_b.status_code(), StatusCode::NO_CONTENT);

        let istag_a = resp_a
            .get_header("ISTag")
            .expect("ISTag /a/scan")
            .to_str()
            .expect("ISTag /a/scan utf8");
        let istag_b = resp_b
            .get_header("ISTag")
            .expect("ISTag /b/scan")
            .to_str()
            .expect("ISTag /b/scan utf8");

        assert!(
            istag_a.contains("svc-a"),
            "expected /a/scan handler (svc-a), got ISTag {istag_a:?}"
        );
        assert!(
            istag_b.contains("svc-b"),
            "expected /b/scan handler (svc-b), got ISTag {istag_b:?}"
        );
        assert_ne!(
            istag_a, istag_b,
            "distinct full paths must resolve to distinct services"
        );
    }

    /// RFC 3507 §6.4 — the shared final segment `/scan` is NOT a registered
    /// service, proving the server no longer falls back to last-segment routing.
    #[tokio::test]
    async fn rfc6_4_last_segment_alone_is_not_a_service() {
        let port = start_full_path_routing_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let resp = client
            .send(
                &Request::reqmod("/scan")
                    .allow_204()
                    .with_http_request(embedded_http_get())
                    .expect("build reqmod /scan"),
            )
            .await
            .expect("send /scan");

        assert_eq!(
            resp.status_code(),
            StatusCode::NOT_FOUND,
            "last-segment-only path must not resolve to /a/scan or /b/scan"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 3507 §5 / §4.10 — Client-side OPTIONS caching and ISTag invalidation
// ---------------------------------------------------------------------------
//
// RFC 3507 §4.10 lets a client cache an OPTIONS response and reuse it for
// subsequent REQMOD/RESPMOD requests until it expires. RFC 3507 §5 requires the
// client to discard that cached entry when the ISTag observed on a later
// modification response differs from the one captured at OPTIONS time. These
// tests verify both behaviors via a minimal raw ICAP server that counts OPTIONS
// requests and can change the ISTag it advertises.

mod section_5_options_cache {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Read an ICAP request head up to the first CRLFCRLF. The §5 requests carry
    // no body (`Encapsulated: null-body=0`), so the head is the whole request.
    async fn read_icap_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
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

    // A raw ICAP server that:
    //   * counts how many OPTIONS requests it received (`options_count`);
    //   * advertises an ISTag derived from `epoch`, so the test can simulate a
    //     server configuration change by bumping `epoch`.
    // Both OPTIONS and modification responses report the same ISTag for a given
    // epoch, so the client only sees a change after the epoch is bumped.
    async fn start_counting_options_server() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let options_count = Arc::new(AtomicUsize::new(0));
        let epoch = Arc::new(AtomicUsize::new(0));

        let oc = Arc::clone(&options_count);
        let ep = Arc::clone(&epoch);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let oc = Arc::clone(&oc);
                let ep = Arc::clone(&ep);
                tokio::spawn(async move {
                    let Some(head) = read_icap_head(&mut stream).await else {
                        return;
                    };
                    let istag = format!("\"epoch-{}\"", ep.load(Ordering::SeqCst));
                    let response = if head.starts_with(b"OPTIONS") {
                        oc.fetch_add(1, Ordering::SeqCst);
                        format!(
                            "ICAP/1.0 200 OK\r\nMethods: REQMOD\r\nISTag: {istag}\r\n\
                             Options-TTL: 3600\r\nEncapsulated: null-body=0\r\n\r\n"
                        )
                    } else {
                        format!(
                            "ICAP/1.0 204 No Content\r\nISTag: {istag}\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                        )
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        (port, options_count, epoch)
    }

    /// RFC 3507 §5 / §4.10 — with the OPTIONS cache enabled, repeated REQMODs
    /// reuse a single cached OPTIONS, and a server `ISTag` change forces a
    /// re-fetch on the following request.
    #[tokio::test]
    async fn rfc5_client_caches_options_and_refetches_on_istag_change() {
        let (port, options_count, epoch) = start_counting_options_server().await;
        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(60)))
            .build();

        // Two REQMODs in a row must share one cached OPTIONS.
        for _ in 0..2 {
            let resp = client
                .send(&Request::reqmod("/scan").allow_204())
                .await
                .expect("reqmod");
            assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        }
        assert_eq!(
            options_count.load(Ordering::SeqCst),
            1,
            "two REQMODs must reuse a single cached OPTIONS"
        );

        // Server changes its ISTag, simulating a configuration/version change.
        epoch.store(1, Ordering::SeqCst);

        // The cached entry is still fresh, so this REQMOD does not re-fetch; it
        // observes the new ISTag on the response and invalidates the cache.
        let resp = client
            .send(&Request::reqmod("/scan").allow_204())
            .await
            .expect("reqmod after istag change");
        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(
            options_count.load(Ordering::SeqCst),
            1,
            "the still-fresh cache entry is used before the ISTag mismatch invalidates it"
        );

        // With the cache invalidated, the next REQMOD re-fetches OPTIONS.
        let resp = client
            .send(&Request::reqmod("/scan").allow_204())
            .await
            .expect("reqmod refetch");
        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(
            options_count.load(Ordering::SeqCst),
            2,
            "an ISTag change must trigger a fresh OPTIONS fetch"
        );
    }
}
