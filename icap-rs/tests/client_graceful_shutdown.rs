/// RFC 3507 §4.2 — Graceful shutdown via `Connection: close`.
///
/// When a client does not intend to reuse the TCP connection it MUST include
/// `Connection: close` in the request so the server knows to close after
/// responding. Conversely, when a client intends to reuse the connection it
/// MUST NOT send `Connection: close`.
///
/// The server MUST honour an incoming `Connection: close` by closing the
/// connection after it has written its response, even when the response itself
/// is a 2xx success.
mod common;

use common::{find_free_port, wait_port_ready};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{Client, HandlerResult, Request};
use icap_rs::request::IncomingRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read ICAP request headers from a raw TCP stream (stops at CRLFCRLF).
async fn read_icap_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.expect("read head");
        assert!(n > 0, "connection closed before ICAP header block");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
}

fn has_connection_close(raw: &str) -> bool {
    raw.split("\r\n")
        .skip(1) // skip request-line
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.trim().eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("close"))
        })
}

// ---------------------------------------------------------------------------
// RFC §4.2 — wire-level unit tests (no real server)
// ---------------------------------------------------------------------------

/// RFC §4.2: `ConnectionPolicy::Close` (the default) MUST send
/// `Connection: close` so the server closes after this request.
#[tokio::test]
async fn rfc4_2_close_policy_sends_connection_close_header() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let head = read_icap_head(&mut stream).await;

        assert!(
            has_connection_close(&head),
            "expected Connection: close in request, got:\n{head}"
        );

        stream
            .write_all(
                b"ICAP/1.0 200 OK\r\n\
ISTag: \"test\"\r\n\
Encapsulated: null-body=0\r\n\
\r\n",
            )
            .await
            .expect("write response");
    });

    // Default ConnectionPolicy is Close.
    let client = Client::builder()
        .host("127.0.0.1")
        .port(port)
        .build();
    let req = Request::options("svc");

    let resp = timeout(Duration::from_secs(2), client.send(&req))
        .await
        .expect("timeout")
        .expect("send");
    assert_eq!(resp.status_code(), StatusCode::OK);

    server.await.expect("fake server task");
}

/// RFC §4.2: `ConnectionPolicy::KeepAlive` MUST NOT send `Connection: close`
/// because the client intends to reuse the connection.
#[tokio::test]
async fn rfc4_2_keep_alive_policy_omits_connection_close_header() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let head = read_icap_head(&mut stream).await;

        assert!(
            !has_connection_close(&head),
            "unexpected Connection: close for keep-alive client:\n{head}"
        );

        stream
            .write_all(
                b"ICAP/1.0 200 OK\r\n\
ISTag: \"test\"\r\n\
Encapsulated: null-body=0\r\n\
\r\n",
            )
            .await
            .expect("write response");
    });

    let client = Client::builder()
        .host("127.0.0.1")
        .port(port)
        .keep_alive(true)
        .build();
    let req = Request::options("svc");

    let resp = timeout(Duration::from_secs(2), client.send(&req))
        .await
        .expect("timeout")
        .expect("send");
    assert_eq!(resp.status_code(), StatusCode::OK);

    server.await.expect("fake server task");
}

/// RFC §4.2: `get_request` wire bytes include `Connection: close` when the
/// client uses `ConnectionPolicy::Close`.
#[test]
fn rfc4_2_wire_bytes_include_connection_close_for_close_policy() {
    let client = Client::builder()
        .host("127.0.0.1")
        .port(1344)
        // ConnectionPolicy::Close is the default
        .build();
    let req = Request::options("svc");
    let bytes = client.get_request(&req).expect("get_request");
    let wire = String::from_utf8(bytes).expect("utf8");

    assert!(
        has_connection_close(&wire),
        "expected Connection: close in wire bytes:\n{wire}"
    );
}

/// RFC §4.2: `get_request` wire bytes omit `Connection: close` when the
/// client uses `ConnectionPolicy::KeepAlive`.
#[test]
fn rfc4_2_wire_bytes_omit_connection_close_for_keep_alive_policy() {
    let client = Client::builder()
        .host("127.0.0.1")
        .port(1344)
        .keep_alive(true)
        .build();
    let req = Request::options("svc");
    let bytes = client.get_request(&req).expect("get_request");
    let wire = String::from_utf8(bytes).expect("utf8");

    assert!(
        !has_connection_close(&wire),
        "unexpected Connection: close for keep-alive policy:\n{wire}"
    );
}

// ---------------------------------------------------------------------------
// RFC §4.2 — server honours Connection: close (integration with real server)
// ---------------------------------------------------------------------------

async fn passthrough_handler(_req: IncomingRequest) -> HandlerResult<Response> {
    Ok(Response::no_content()
        .try_set_istag("test")
        .expect("istag"))
}

async fn start_test_server() -> u16 {
    let port = find_free_port();
    let addr = format!("127.0.0.1:{port}");
    let opts = ServiceOptions::new()
        .with_static_istag("test-1.0")
        .with_service("Test");

    let server = Server::builder()
        .bind(&addr)
        .route_reqmod("svc", passthrough_handler, Some(opts))
        .build()
        .await
        .expect("build server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    wait_port_ready(&addr).await;
    port
}

/// RFC §4.2: when the client sends `Connection: close`, the server MUST close
/// the TCP connection after writing its response, even for a 2xx reply.
///
/// We verify this by connecting with a raw socket, sending a well-formed
/// OPTIONS request that includes `Connection: close`, reading the response,
/// and asserting that the next read returns EOF (0 bytes).
#[tokio::test]
async fn rfc4_2_server_closes_connection_after_client_connection_close() {
    let port = start_test_server().await;
    let addr = format!("127.0.0.1:{port}");

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .expect("connect");

    // Hand-crafted OPTIONS with Connection: close.
    let request = format!(
        "OPTIONS icap://127.0.0.1:{port}/svc ICAP/1.0\r\n\
Host: 127.0.0.1\r\n\
Connection: close\r\n\
Encapsulated: null-body=0\r\n\
\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush");

    // Read until CRLFCRLF (the ICAP response headers).
    let mut resp_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = timeout(Duration::from_secs(2), stream.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read");
        assert!(n > 0, "EOF before response headers were received");
        resp_buf.extend_from_slice(&tmp[..n]);
        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(
        resp_str.starts_with("ICAP/1.0 200"),
        "unexpected response: {resp_str}"
    );

    // The server must close the connection: next read should return 0 bytes (EOF).
    let n = timeout(Duration::from_secs(2), stream.read(&mut tmp))
        .await
        .expect("close timeout")
        .expect("read after response");
    assert_eq!(
        n, 0,
        "expected server to close the connection (EOF), got {n} bytes"
    );
}

/// RFC §4.2: when the server's response carries `Connection: close`, the
/// client discards the connection (does not put it back in the keep-alive pool)
/// and opens a fresh TCP connection for the next request.
#[tokio::test]
async fn rfc4_2_client_does_not_reuse_connection_after_server_sends_connection_close() {
    // Fake server: first connection gets a 404 (server adds Connection: close
    // automatically for non-2xx). Second request must come on a *new* connection.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let addr = listener.local_addr().expect("local addr");
    let port = addr.port();

    let server = tokio::spawn(async move {
        // First connection: accept, respond with 404 (triggers Connection: close).
        let (mut s1, _) = listener.accept().await.expect("accept 1");
        let _head = read_icap_head(&mut s1).await;
        s1.write_all(
            b"ICAP/1.0 404 Not Found\r\n\
ISTag: \"t\"\r\n\
Connection: close\r\n\
Encapsulated: null-body=0\r\n\
\r\n",
        )
        .await
        .expect("write 404");
        drop(s1);

        // Second connection: accept and send 200.
        let (mut s2, _) = listener.accept().await.expect("accept 2");
        let _head = read_icap_head(&mut s2).await;
        s2.write_all(
            b"ICAP/1.0 200 OK\r\n\
ISTag: \"t\"\r\n\
Encapsulated: null-body=0\r\n\
\r\n",
        )
        .await
        .expect("write 200");
    });

    let client = Client::builder()
        .host("127.0.0.1")
        .port(port)
        .keep_alive(true)
        .build();
    let req = Request::options("svc");

    // First send — gets the 404.
    let r1 = timeout(Duration::from_secs(2), client.send(&req))
        .await
        .expect("timeout 1")
        .expect("send 1");
    assert_eq!(r1.status_code(), StatusCode::NOT_FOUND);

    // Second send — must open a new connection (server accepted twice).
    let r2 = timeout(Duration::from_secs(2), client.send(&req))
        .await
        .expect("timeout 2")
        .expect("send 2");
    assert_eq!(r2.status_code(), StatusCode::OK);

    server.await.expect("fake server task");
}
