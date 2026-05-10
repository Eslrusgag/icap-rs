//! RFC 3507 integration conformance matrix.
//!
//! The test names intentionally encode the support status and the supported
//! variation. `supported_*` tests are release assertions. `unsupported_*`
//! tests are ignored placeholders for visible RFC gaps that should not be
//! mistaken for implemented behavior.

use http::{Request as HttpRequest, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::error::IcapResult;
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::options::{ServiceOptions, TransferBehavior};
use icap_rs::server::{PreviewDecision, Server};
use icap_rs::{Client, Method};
use std::net::TcpListener as StdTcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;

const ISTAG: &str = "rfc3507";

async fn no_modification_handler(_req: Request) -> IcapResult<Response> {
    Response::no_content().try_set_istag(ISTAG)
}

async fn preview_final_handler(_req: Request) -> IcapResult<PreviewDecision> {
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
            .get_request(&Request::reqmod("scan").with_http_request(http))
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
        let parsed = Response::from_raw(
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
            parsed.body,
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
}

mod sections_4_6_and_4_7_responses {
    use super::*;

    #[tokio::test]
    async fn supported_204_requires_allow_or_preview_otherwise_server_returns_200() {
        let port = start_respmod_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let no_allow = client
            .send(&Request::respmod("respmod").with_http_response(embedded_http_response("hello")))
            .await
            .expect("send without allow");
        assert_eq!(no_allow.status_code, StatusCode::OK);

        let allow_204 = client
            .send(
                &Request::respmod("respmod")
                    .allow_204()
                    .with_http_response(embedded_http_response("hello")),
            )
            .await
            .expect("send allow 204");
        assert_eq!(allow_204.status_code, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn supported_206_uses_original_body_marker_for_no_modification() {
        let port = start_respmod_server().await;
        let client = Client::builder().host("127.0.0.1").port(port).build();

        let response = client
            .send(
                &Request::respmod("respmod")
                    .allow_206()
                    .with_http_response(embedded_http_response("hello")),
            )
            .await
            .expect("send allow 206");

        assert_eq!(response.status_code, StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.use_original_body_offset(), Some(0));
        assert!(!String::from_utf8_lossy(&response.body).contains("hello"));
    }

    #[test]
    fn supported_success_responses_require_istag() {
        let err = Response::from_raw(b"ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n")
            .expect_err("2xx without ISTag must fail");

        assert!(err.to_string().contains("ISTag"));
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

        assert_eq!(response.status_code, StatusCode::OK);
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
    #[ignore = "partial support only: headers exist, but client-side OPTIONS/cache invalidation model is not implemented"]
    fn unsupported_section_5_client_cache_semantics() {}

    #[test]
    #[ignore = "partial support only: server advertises Transfer-* but client does not automatically apply transfer policy"]
    fn unsupported_section_4_10_2_automatic_transfer_policy_consumption() {}

    #[test]
    #[ignore = "partial support only: server routes by final path segment, not full RFC service URI identity"]
    fn unsupported_section_6_4_full_service_uri_model() {}

    #[test]
    #[ignore = "partial support only: chunk extensions are parsed for ieof/use-original-body, but trailers have no structured API"]
    fn unsupported_section_6_3_structured_chunk_trailers() {}
}
