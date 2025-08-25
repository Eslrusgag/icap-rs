use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use icap_rs::server::Server;

async fn pick_free_port() -> io::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

/// Start a server on 127.0.0.1:{port} with a global connection limit.
async fn start_server_with_limit(
    limit: usize,
) -> Result<(tokio::task::JoinHandle<()>, u16), io::Error> {
    let port = pick_free_port().await?;
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .with_max_connections(limit)
        .build()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("build: {e}")))?;

    // Spawn the server.
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give the server a moment to bind.
    sleep(Duration::from_millis(50)).await;
    Ok((handle, port))
}

/// Read a small chunk with a timeout.
/// Ok(Some(n)) — read n bytes; Ok(None) — EOF; Ok(Some(0)) — timed out (socket still open).
async fn read_some_with_timeout(s: &mut TcpStream, ms: u64) -> io::Result<Option<usize>> {
    match timeout(Duration::from_millis(ms), s.read(&mut [0u8; 4096])).await {
        Ok(Ok(0)) => Ok(None),
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(Some(0)), // timeout (socket alive)
    }
}

/// Minimal ICAP OPTIONS request.
fn build_options(port: u16, svc: &str) -> Vec<u8> {
    format!("OPTIONS icap://127.0.0.1:{port}/{svc} ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respects_global_max_connections() -> Result<(), std::io::Error> {
    let (_srv, port) = start_server_with_limit(1).await?;

    // First connection occupies the permit.
    let _hold = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    // Second connection should receive ICAP 503.
    let mut c2 = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut buf = vec![0u8; 2048];
    let n =
        tokio::time::timeout(std::time::Duration::from_millis(500), c2.read(&mut buf)).await??;
    assert!(n > 0, "expected to receive ICAP 503 response bytes");

    let head = String::from_utf8_lossy(&buf[..n]).to_ascii_uppercase();
    assert!(
        head.starts_with("ICAP/1.0 503"),
        "expected ICAP/1.0 503 status line, got:\n{head}"
    );
    assert!(
        head.contains("ENCAPSULATED: NULL-BODY=0"),
        "expected 'Encapsulated: null-body=0', got:\n{head}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_advertises_global_limit_in_default_response() -> Result<(), io::Error> {
    let (_srv, port) = start_server_with_limit(3).await?;

    let mut c = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = build_options(port, "unknown");
    c.write_all(&req).await?;

    let mut buf = Vec::with_capacity(4096);
    let n = timeout(Duration::from_millis(500), c.read_buf(&mut buf)).await??;
    assert!(n > 0, "expected some response bytes");

    let s = String::from_utf8_lossy(&buf);
    assert!(s.starts_with("ICAP/1.0 "), "not an ICAP response:\n{s}");
    assert!(
        s.to_ascii_lowercase().contains("max-connections: 3"),
        "OPTIONS must advertise Max-Connections: 3\n{s}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allows_two_connections_when_limit_is_two() -> Result<(), io::Error> {
    let (_srv, port) = start_server_with_limit(2).await?;

    let mut c1 = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut c2 = TcpStream::connect(("127.0.0.1", port)).await?;

    // Timeout (Some(0)) is acceptable; only EOF (None) is not.
    let r1 = read_some_with_timeout(&mut c1, 200).await?;
    let r2 = read_some_with_timeout(&mut c2, 200).await?;
    assert!(r1.is_some(), "conn1 should still be open");
    assert!(r2.is_some(), "conn2 should still be open");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_503_when_over_connection_limit() -> Result<(), io::Error> {
    let (_srv, port) = start_server_with_limit(1).await?;

    // First connection occupies the permit.
    let _hold = TcpStream::connect(("127.0.0.1", port)).await?;
    sleep(Duration::from_millis(30)).await;

    // Second connection should immediately get ICAP/1.0 503.
    let mut c2 = TcpStream::connect(("127.0.0.1", port)).await?;

    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_millis(500), c2.read(&mut buf)).await??;
    assert!(n > 0, "expected to receive ICAP 503 response bytes, got 0");

    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let start = text.lines().next().unwrap_or_default().to_ascii_uppercase();

    assert!(
        start.starts_with("ICAP/1.0 503"),
        "expected ICAP/1.0 503 status line, got:\n{}",
        start
    );

    // Also check Encapsulated and absence of a body.
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("encapsulated: null-body=0"),
        "expected 'Encapsulated: null-body=0' header, got:\n{}",
        text
    );

    Ok(())
}
