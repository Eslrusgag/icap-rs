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
        .with_max_object_size(4096)
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

const OPT_BODY: &[u8] = b"server info";

async fn start_opt_body_options_server() -> u16 {
    let port = unused_port();
    let options = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("RFC 3507 opt-body service")
        .with_opt_body("text/plain", OPT_BODY.to_vec());
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_respmod("info", no_modification_handler, Some(options))
        .build()
        .await
        .expect("build opt-body options server");

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

mod header_limits {
    use super::*;

    #[tokio::test]
    async fn rfc3507_server_rejects_icap_request_headers_over_configured_limit() {
        let port = unused_port();
        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .with_request_header_limit(128)
            .route_reqmod(
                "scan",
                no_modification_handler,
                Some(ServiceOptions::new().with_static_istag(ISTAG)),
            )
            .build()
            .await
            .expect("build limited server");

        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let filler = "a".repeat(256);
        let request = format!(
            "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             X-Fill: {filler}\r\n\
             Encapsulated: null-body=0\r\n\r\n"
        );

        let raw = send_raw_icap_request(port, &request).await;
        assert_eq!(first_line(&raw), "ICAP/1.0 400 Request Header Too Large");
        assert!(
            String::from_utf8_lossy(&raw).contains("Request Header Too Large"),
            "wire response should identify the oversized ICAP request header"
        );
    }

    #[tokio::test]
    async fn rfc3507_client_rejects_icap_response_headers_over_configured_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request_buf = [0_u8; 512];
            let _ = stream.read(&mut request_buf).await;

            let filler = "a".repeat(256);
            let response = format!(
                "ICAP/1.0 204 No Content\r\n\
                 X-Fill: {filler}\r\n\
                 Encapsulated: null-body=0\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .with_response_header_limit(128)
            .build();
        let err = client
            .send(&Request::options("scan"))
            .await
            .expect_err("oversized ICAP response header should fail");

        assert!(err.is_protocol());
        assert!(
            err.to_string().contains("ICAP response headers too large"),
            "error should preserve the protocol-level header limit failure"
        );
    }
}

mod body_limits {
    use super::*;

    async fn start_body_limited_server(max_object_size: usize) -> u16 {
        let port = unused_port();
        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .route_reqmod(
                "scan",
                no_modification_handler,
                Some(
                    ServiceOptions::new()
                        .with_static_istag(ISTAG)
                        .with_max_object_size(max_object_size),
                ),
            )
            .build()
            .await
            .expect("build body-limited server");

        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    async fn start_per_service_body_limit_server() -> u16 {
        let port = unused_port();
        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .route_reqmod(
                "small",
                no_modification_handler,
                Some(
                    ServiceOptions::new()
                        .with_static_istag(ISTAG)
                        .with_max_object_size(4),
                ),
            )
            .route_reqmod(
                "large",
                no_modification_handler,
                Some(
                    ServiceOptions::new()
                        .with_static_istag(ISTAG)
                        .with_max_object_size(16),
                ),
            )
            .build()
            .await
            .expect("build per-service body-limited server");

        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    #[tokio::test]
    async fn rfc3507_service_counts_actual_body_not_content_length_for_max_object_size() {
        let port = start_body_limited_server(4).await;
        let http_head = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\n\r\n";
        let req_body_offset = http_head.len();
        let request = format!(
            "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Allow: 204\r\n\
             Encapsulated: req-hdr=0, req-body={req_body_offset}\r\n\r\n\
             {http_head}\
             3\r\nabc\r\n0\r\n\r\n"
        );

        let raw = send_raw_icap_request(port, &request).await;
        assert_eq!(first_line(&raw), "ICAP/1.0 204 No Content");
    }

    #[tokio::test]
    async fn rfc3507_service_does_not_trust_null_body_content_length_for_max_object_size() {
        let port = start_body_limited_server(4).await;
        let http_head = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\n\r\n";
        let null_body_offset = http_head.len();
        let request = format!(
            "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Allow: 204\r\n\
             Encapsulated: req-hdr=0, null-body={null_body_offset}\r\n\r\n\
             {http_head}"
        );

        let raw = send_raw_icap_request(port, &request).await;
        assert_eq!(first_line(&raw), "ICAP/1.0 204 No Content");
    }

    #[tokio::test]
    async fn rfc3507_service_rejects_actual_body_over_max_object_size() {
        let port = start_body_limited_server(4).await;
        let http_head = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n";
        let req_body_offset = http_head.len();
        let request = format!(
            "REQMOD icap://127.0.0.1:{port}/scan ICAP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Encapsulated: req-hdr=0, req-body={req_body_offset}\r\n\r\n\
             {http_head}\
             6\r\nabcdef\r\n0\r\n\r\n"
        );

        let raw = send_raw_icap_request(port, &request).await;
        assert_eq!(first_line(&raw), "ICAP/1.0 413 Payload Too Large");
    }

    #[tokio::test]
    async fn rfc3507_max_object_size_is_service_specific_options_policy() {
        let port = start_per_service_body_limit_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let small_options = client
            .send(&Request::options("small"))
            .await
            .expect("small options");
        let large_options = client
            .send(&Request::options("large"))
            .await
            .expect("large options");

        assert_eq!(
            small_options
                .get_header("Max-Object-Size")
                .expect("small Max-Object-Size"),
            "4"
        );
        assert_eq!(
            large_options
                .get_header("Max-Object-Size")
                .expect("large Max-Object-Size"),
            "16"
        );

        let http_head = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8\r\n\r\n";
        let req_body_offset = http_head.len();
        let request = format!(
            "REQMOD icap://127.0.0.1:{port}/large ICAP/1.0\r\n\
             Host: 127.0.0.1\r\n\
             Allow: 204\r\n\
             Encapsulated: req-hdr=0, req-body={req_body_offset}\r\n\r\n\
             {http_head}\
             8\r\nabcdefgh\r\n0\r\n\r\n"
        );

        let raw = send_raw_icap_request(port, &request).await;
        assert_eq!(first_line(&raw), "ICAP/1.0 204 No Content");
    }
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

    /// RFC 3507 §4.7 — a handler may return `206 Partial Content` with a
    /// modified HTTP head and the `use-original-body` marker, instructing the
    /// client to append the original body starting at the given offset.
    /// This test exercises the explicit server-side path via
    /// `Response::with_http_response_head_and_original_body`.
    #[tokio::test]
    async fn supported_206_explicit_handler_adds_header_and_keeps_original_body() {
        use icap_rs::EmbeddedHttp;

        let port = {
            let p = unused_port();
            let server = Server::builder()
                .bind(&format!("127.0.0.1:{p}"))
                .route_respmod(
                    "respmod",
                    |req: IncomingRequest| async move {
                        let embedded = req
                            .into_embedded()
                            .expect("RESPMOD must have embedded HTTP");
                        let EmbeddedHttp::Resp { head, .. } = embedded else {
                            return Ok(Response::no_content_with_istag(ISTAG)?);
                        };
                        // Add a custom header to the HTTP response head and
                        // instruct the client to reuse the original body.
                        let (mut parts, ()) = head.into_parts();
                        parts.headers.insert(
                            http::HeaderName::from_static("x-icap-scanned"),
                            http::HeaderValue::from_static("yes"),
                        );
                        let modified = HttpResponse::from_parts(parts, ());
                        Ok(Response::partial_content_with_istag(ISTAG)?
                            .with_http_response_head_and_original_body(&modified, 0)?)
                    },
                    Some(
                        ServiceOptions::new()
                            .with_static_istag(ISTAG)
                            .with_service("RFC 3507 explicit 206")
                            .add_allow("206"),
                    ),
                )
                .build()
                .await
                .expect("build explicit-206 server");
            tokio::spawn(async move {
                let _ = server.run().await;
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            p
        };

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let response = client
            .send(
                &Request::respmod("respmod")
                    .allow_206()
                    .with_http_response(embedded_http_response("original body"))
                    .expect("build respmod request"),
            )
            .await
            .expect("send allow 206 explicit handler");

        assert_eq!(response.status_code(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.use_original_body_offset(),
            Some(0),
            "use-original-body marker must be at offset 0"
        );
        // The modified HTTP head must be present in the ICAP response body.
        let body_str = String::from_utf8_lossy(response.body()).to_ascii_lowercase();
        assert!(
            body_str.contains("x-icap-scanned: yes"),
            "modified HTTP head must contain the injected header; got:\n{body_str}"
        );
        // The original entity body must NOT appear in the ICAP response.
        assert!(
            !body_str.contains("original body"),
            "original HTTP body must not be echoed in a 206 response; got:\n{body_str}"
        );
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
                .get_header("Max-Object-Size")
                .expect("Max-Object-Size"),
            "4096"
        );
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

    /// RFC 3507 §4.10: an `OPTIONS` response may carry an opt-body advertised via
    /// `Encapsulated: opt-body=0` and described by `Opt-body-type`. The entity is
    /// ICAP-chunked on the wire; the client dechunks it into `Response::body()`.
    #[tokio::test]
    async fn supported_service_options_emit_chunked_opt_body() {
        let port = start_opt_body_options_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();
        let response = client
            .send(&Request::options("info"))
            .await
            .expect("send options");

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(
            response.get_header("Encapsulated").expect("Encapsulated"),
            "opt-body=0"
        );
        assert_eq!(
            response.get_header("Opt-body-type").expect("Opt-body-type"),
            "text/plain"
        );
        // The ICAP-chunked opt-body round-trips back to the original bytes.
        assert_eq!(response.body(), OPT_BODY);
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
            .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_mins(1)))
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

// ---------------------------------------------------------------------------
// RFC 3507 §4.10.2 — Client-side Transfer-* policy consumption
// ---------------------------------------------------------------------------
//
// The server MAY advertise Transfer-Preview, Transfer-Ignore, and
// Transfer-Complete in its OPTIONS response. The client MUST apply the policy
// that matches the request's file extension (RFC 3507 §4.10.2):
//
//   Transfer-Complete (highest priority): send the full body, no Preview header.
//   Transfer-Ignore:                      bypass ICAP; return a synthetic 204.
//   Transfer-Preview (lowest priority):   send N bytes as preview, wait for 100 Continue.
//
// These tests use a raw TCP server so Transfer-* headers can be included in
// the OPTIONS response without modifying the server-side ServiceOptions API.

mod section_4_10_2_transfer_policy {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Read until the first CRLFCRLF — works for null-body and header-only ICAP messages.
    async fn read_icap_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
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

    /// Start a raw ICAP server that advertises Transfer-* policy in OPTIONS.
    ///
    /// - OPTIONS -> 200 with `Transfer-Ignore: jpg`,
    ///   `Transfer-Preview: html`, and `Transfer-Complete: gif`
    ///   (`Preview: 512`, `Options-TTL: 3600`)
    /// - REQMOD -> 204 No Content; increments `reqmod_count`
    ///
    /// Returns `(port, reqmod_count, received_preview_size)`.
    /// `received_preview_size` is set to the `Preview` header value from the
    /// REQMOD request (or 0 if no Preview header).
    async fn start_transfer_policy_server() -> (
        u16,
        Arc<AtomicUsize>,
        Arc<tokio::sync::Mutex<Option<usize>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let reqmod_count = Arc::new(AtomicUsize::new(0));
        let preview_seen = Arc::new(tokio::sync::Mutex::new(None));

        let rc = Arc::clone(&reqmod_count);
        let ps = Arc::clone(&preview_seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let rc = Arc::clone(&rc);
                let ps = Arc::clone(&ps);
                tokio::spawn(async move {
                    loop {
                        let Some(head) = read_icap_head(&mut stream).await else {
                            return;
                        };
                        let head_str = String::from_utf8_lossy(&head);
                        let resp = if head_str.starts_with("OPTIONS") {
                            "ICAP/1.0 200 OK\r\n\
                             ISTag: \"transfer-test\"\r\n\
                             Options-TTL: 3600\r\n\
                             Transfer-Ignore: jpg\r\n\
                             Transfer-Preview: html\r\n\
                             Transfer-Complete: gif\r\n\
                             Preview: 512\r\n\
                             Methods: REQMOD\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                                .to_string()
                        } else {
                            // REQMOD — record whether the request carried a Preview header
                            let preview = head_str
                                .lines()
                                .find(|l| l.to_ascii_lowercase().starts_with("preview:"))
                                .and_then(|l| l.split(':').nth(1))
                                .and_then(|v| v.trim().parse::<usize>().ok());
                            *ps.lock().await = preview;
                            rc.fetch_add(1, Ordering::SeqCst);
                            "ICAP/1.0 204 No Content\r\n\
                             ISTag: \"transfer-test\"\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                                .to_string()
                        };
                        if stream.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                    }
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (port, reqmod_count, preview_seen)
    }

    fn reqmod_for(uri: &str) -> Request {
        let http_req = HttpRequest::builder()
            .method("GET")
            .uri(uri)
            .version(Version::HTTP_11)
            .header("Host", "example.com")
            .body(Vec::new())
            .expect("build http request");
        Request::reqmod("/reqmod")
            .allow_204()
            .with_http_request(http_req)
            .expect("build reqmod")
    }

    /// RFC 3507 §4.10.2 — Transfer-Ignore: the client returns a synthetic 204
    /// without contacting the server for extensions listed in Transfer-Ignore.
    #[tokio::test]
    async fn rfc4_10_2_transfer_ignore_bypasses_icap() {
        // RFC 3507 §4.10.2
        let (port, reqmod_count, _) = start_transfer_policy_server().await;
        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_mins(1)))
            .build();

        let resp = client
            .send(&reqmod_for("http://example.com/photo.jpg"))
            .await
            .expect("send");

        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(
            reqmod_count.load(Ordering::SeqCst),
            0,
            "Transfer-Ignore must bypass ICAP — no REQMOD should reach the server"
        );
    }

    /// RFC 3507 §4.10.2 — Transfer-Preview: the client sends the first N bytes
    /// as preview and waits for 100 Continue.
    #[tokio::test]
    async fn rfc4_10_2_transfer_preview_overrides_request_preview_size() {
        // RFC 3507 §4.10.2
        let (port, reqmod_count, preview_seen) = start_transfer_policy_server().await;
        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_mins(1)))
            .build();

        // Request has NO preview set; Transfer-Preview: html should force Preview: 512.
        let resp = client
            .send(&reqmod_for("http://example.com/page.html"))
            .await
            .expect("send");

        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(
            reqmod_count.load(Ordering::SeqCst),
            1,
            "REQMOD must reach server"
        );
        assert_eq!(
            *preview_seen.lock().await,
            Some(512),
            "Transfer-Preview must inject Preview: 512 from OPTIONS"
        );
    }

    /// RFC 3507 §4.10.2 — Transfer-Complete: the client sends the full body
    /// with no Preview header.
    #[tokio::test]
    async fn rfc4_10_2_transfer_complete_sends_full_body_no_preview() {
        // RFC 3507 §4.10.2
        let (port, reqmod_count, preview_seen) = start_transfer_policy_server().await;
        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .with_options_cache(OptionsCacheConfig::new().with_default_ttl(Duration::from_mins(1)))
            .build();

        let resp = client
            .send(&reqmod_for("http://example.com/icon.gif"))
            .await
            .expect("send");

        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);
        assert_eq!(
            reqmod_count.load(Ordering::SeqCst),
            1,
            "REQMOD must reach server"
        );
        assert_eq!(
            *preview_seen.lock().await,
            None,
            "Transfer-Complete must not include a Preview header"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 3507 §7.1 — Proxy authentication
// ---------------------------------------------------------------------------
//
// RFC 3507 §7.1 describes proxy authentication via 407 Proxy Authentication
// Required and the Proxy-Authorization header. The client MUST retry the
// request once with credentials when it receives a 407 and credentials are
// configured.

mod section_7_1_proxy_authentication {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn read_icap_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
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

    /// Start a raw ICAP server that:
    /// - returns 407 Proxy Authentication Required on the first `REQMOD`;
    /// - returns 204 No Content on the second `REQMOD` with credentials.
    ///
    /// Returns `(port, request_count, last_proxy_auth_header)`.
    async fn start_auth_server() -> (u16, Arc<AtomicUsize>, Arc<tokio::sync::Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let request_count = Arc::new(AtomicUsize::new(0));
        let last_auth = Arc::new(tokio::sync::Mutex::new(String::new()));

        let rc = Arc::clone(&request_count);
        let la = Arc::clone(&last_auth);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let rc = Arc::clone(&rc);
                let la = Arc::clone(&la);
                tokio::spawn(async move {
                    loop {
                        let Some(head) = read_icap_head(&mut stream).await else {
                            return;
                        };
                        let head_str = String::from_utf8_lossy(&head);
                        let n = rc.fetch_add(1, Ordering::SeqCst) + 1;

                        // Record the Proxy-Authorization header if present.
                        if let Some(auth_line) = head_str
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
                        {
                            *la.lock().await = auth_line
                                .split_once(':')
                                .map_or("", |(_, value)| value)
                                .trim()
                                .to_string();
                        }

                        let resp = if n == 1 {
                            // First request: challenge
                            "ICAP/1.0 407 Proxy Authentication Required\r\n\
                             Proxy-Authenticate: Basic realm=\"icap-test\"\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                                .to_string()
                        } else {
                            // Subsequent requests: accept
                            "ICAP/1.0 204 No Content\r\n\
                             ISTag: \"auth-ok\"\r\n\
                             Encapsulated: null-body=0\r\n\r\n"
                                .to_string()
                        };
                        if stream.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                    }
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (port, request_count, last_auth)
    }

    /// RFC 3507 §7.1 — the client retries with Basic credentials on 407, and
    /// the Proxy-Authorization header uses the correct base64 encoding.
    #[tokio::test]
    async fn rfc7_1_client_retries_with_proxy_authorization_on_407() {
        // RFC 3507 §7.1
        let (port, request_count, last_auth) = start_auth_server().await;

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .proxy_auth("alice", "hunter2")
            .build();

        let resp = client
            .send(&Request::reqmod("/reqmod").allow_204())
            .await
            .expect("send with proxy auth");

        assert_eq!(
            resp.status_code(),
            StatusCode::NO_CONTENT,
            "retry with credentials must succeed"
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            2,
            "exactly two requests expected: 407 challenge + authenticated retry"
        );

        // Verify the Proxy-Authorization value: Basic base64("alice:hunter2")
        // "alice:hunter2" → YWxpY2U6aHVudGVyMg==
        let auth = last_auth.lock().await.clone();
        assert_eq!(
            auth, "Basic YWxpY2U6aHVudGVyMg==",
            "Proxy-Authorization must use Basic scheme with correct base64"
        );
    }

    /// RFC 3507 §7.1 — without credentials configured the 407 is returned
    /// to the caller as-is (no retry).
    #[tokio::test]
    async fn rfc7_1_no_credentials_returns_407_to_caller() {
        // RFC 3507 §7.1
        let (port, request_count, _) = start_auth_server().await;

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            // no .proxy_auth()
            .build();

        let resp = client
            .send(&Request::reqmod("/reqmod").allow_204())
            .await
            .expect("send without proxy auth");

        assert_eq!(
            resp.status_code(),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            1,
            "without credentials only one request is sent"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 3507 §4.4.1 — RESPMOD optional req-hdr context
// ---------------------------------------------------------------------------
//
// A RESPMOD request MAY carry the originating HTTP request headers in a
// `req-hdr` section, in addition to `res-hdr` and `res-body`.  The grammar
// (RFC 3507 §4.4.1) explicitly allows this:
//
//   RESPMOD request  encapsulated_list: [reqhdr] [reshdr] resbody
//
// The server MUST parse it and expose it to handlers via
// `EmbeddedHttp::respmod_request_head()`.

mod section_4_4_1_respmod_req_hdr {
    use super::*;
    use icap_rs::request::EmbeddedHttp;
    use tokio::io::AsyncWriteExt;

    async fn start_req_hdr_capture_server(tx: tokio::sync::oneshot::Sender<Option<String>>) -> u16 {
        let port = unused_port();
        let tx = std::sync::Mutex::new(Some(tx));
        let handler = move |req: IncomingRequest| {
            let captured = req
                .embedded()
                .and_then(EmbeddedHttp::respmod_request_head)
                .and_then(|h| h.headers().get("x-original-req"))
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let sender = tx.lock().unwrap().take();
            async move {
                if let Some(s) = sender {
                    let _ = s.send(captured);
                }
                Ok::<Response, icap_rs::HandlerError>(Response::no_content().try_set_istag(ISTAG)?)
            }
        };
        let server = Server::builder()
            .bind(&format!("127.0.0.1:{port}"))
            .route_respmod(
                "respmod",
                handler,
                Some(
                    ServiceOptions::new()
                        .with_static_istag(ISTAG)
                        .add_allow("204"),
                ),
            )
            .build()
            .await
            .expect("build req-hdr server");
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        port
    }

    /// RFC 3507 §4.4.1 — when a RESPMOD request includes `req-hdr`, the server
    /// parses and exposes the HTTP request context to handlers.
    #[tokio::test]
    async fn rfc4_4_1_respmod_req_hdr_is_parsed_and_exposed_to_handler() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
        let port = start_req_hdr_capture_server(tx).await;

        // Build the req-hdr section: minimal HTTP request head.
        let http_req_bytes =
            b"GET /resource HTTP/1.1\r\nHost: origin.example\r\nX-Original-Req: marker-123\r\n\r\n";
        let http_req_len = http_req_bytes.len();

        // Build the res-hdr section: HTTP response head.
        let http_resp_bytes =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n";
        let http_resp_len = http_resp_bytes.len();

        // res-body: chunked body
        let res_body = b"5\r\nhello\r\n0\r\n\r\n";

        let res_hdr_offset = http_req_len;
        let res_body_offset = http_req_len + http_resp_len;

        let icap_head = format!(
            "RESPMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Allow: 204\r\n\
             Encapsulated: req-hdr=0, res-hdr={res_hdr_offset}, res-body={res_body_offset}\r\n\
             \r\n"
        );

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        stream
            .write_all(icap_head.as_bytes())
            .await
            .expect("write icap head");
        stream
            .write_all(http_req_bytes)
            .await
            .expect("write req head");
        stream
            .write_all(http_resp_bytes)
            .await
            .expect("write res head");
        stream.write_all(res_body).await.expect("write res body");
        stream.flush().await.expect("flush");

        let mut buf = vec![0u8; 4096];
        let _n = stream.read(&mut buf).await.expect("read response");

        let captured = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .expect("recv");

        assert_eq!(
            captured.as_deref(),
            Some("marker-123"),
            "handler must see X-Original-Req from req-hdr context"
        );
    }

    /// RFC 3507 §4.4.1 — RESPMOD without `req-hdr`: `req_head` is `None`, handler works normally.
    #[tokio::test]
    async fn rfc4_4_1_respmod_without_req_hdr_req_head_is_none() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
        let port = start_req_hdr_capture_server(tx).await;

        let res_head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n";
        let res_head_len = res_head.len();
        let res_body = b"5\r\nhello\r\n0\r\n\r\n";

        let icap_head = format!(
            "RESPMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Allow: 204\r\n\
             Encapsulated: res-hdr=0, res-body={res_head_len}\r\n\
             \r\n"
        );

        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");
        stream
            .write_all(icap_head.as_bytes())
            .await
            .expect("write icap head");
        stream.write_all(res_head).await.expect("write res head");
        stream.write_all(res_body).await.expect("write res body");
        stream.flush().await.expect("flush");

        let mut buf = vec![0u8; 4096];
        let _n = stream.read(&mut buf).await.expect("read response");

        let captured = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("timeout")
            .expect("recv");

        assert!(
            captured.is_none(),
            "req_head must be None when no req-hdr was sent"
        );
    }

    /// RFC 3507 §4.4.1 — client can include req-hdr context when sending RESPMOD.
    #[test]
    fn rfc4_4_1_client_builder_with_request_context_sets_req_head() {
        let orig_req = HttpRequest::builder()
            .method("GET")
            .uri("/resource")
            .version(Version::HTTP_11)
            .header("Host", "origin.example")
            .body(())
            .expect("http request");

        let http_resp = HttpResponse::builder()
            .status(HttpStatus::OK)
            .version(Version::HTTP_11)
            .header("Content-Type", "text/html")
            .body(b"hello".to_vec())
            .expect("http response");

        let req = Request::respmod("respmod")
            .with_http_response_and_request_context(http_resp, orig_req)
            .expect("build respmod with req context");

        match req.embedded() {
            Some(EmbeddedHttp::Resp { req_head, .. }) => {
                let head = req_head.as_ref().expect("req_head must be Some");
                assert_eq!(head.uri(), "/resource");
                assert_eq!(
                    head.headers().get("Host").and_then(|v| v.to_str().ok()),
                    Some("origin.example")
                );
            }
            _ => panic!("expected EmbeddedHttp::Resp"),
        }
    }
}
