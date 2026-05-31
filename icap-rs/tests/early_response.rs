use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};

use icap_rs::client::Client;
use icap_rs::error::Error;
use icap_rs::request::{IncomingRequest, Request};
use icap_rs::response::{ParsedResponse, Response, StatusCode};
use icap_rs::server::ServiceOptions;

fn find_free_port() -> u16 {
    let sock = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    sock.local_addr().unwrap().port()
}

async fn spawn_server_with_limit(limit: usize) -> (String, JoinHandle<()>) {
    let port = find_free_port();
    let addr = format!("127.0.0.1:{port}");

    let server = icap_rs::server::Server::builder()
        .bind(&addr)
        .with_max_connections(limit)
        .route_reqmod(
            "svc-options",
            |_: IncomingRequest| async move {
                Ok(Response::new(StatusCode::OK, "OK")
                    .try_set_istag("x")
                    .unwrap())
            },
            Some(ServiceOptions::new().with_static_istag("svc-options-1.0")),
        )
        .build()
        .await
        .expect("server build failed");

    let h = tokio::spawn(async move {
        let _ = server.run().await;
    });

    wait_port_ready(&addr).await;
    (addr, h)
}

async fn wait_port_ready(addr: &str) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start listening on {addr}");
}

fn make_client(host: &str, port: u16) -> Client {
    Client::builder()
        .host(host)
        .port(port)
        .keep_alive(false)
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_503_when_conn_limit_exceeded() {
    let (addr, _handle) = spawn_server_with_limit(1).await;
    let sa: SocketAddr = addr.parse().unwrap();
    let req = Request::options("svc-options");

    // Deterministically occupy the single connection permit. A keep-alive client
    // that *successfully* completes one request (200 OK) is provably the connection
    // holding the permit, and keeps the connection open afterwards so the permit
    // stays held. We retry because the startup readiness probe may transiently hold
    // the only permit right after bind, which would 503 our first attempt.
    let hold_client = Client::builder()
        .host("127.0.0.1")
        .port(sa.port())
        .keep_alive(true)
        .build();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match timeout(Duration::from_millis(200), hold_client.send(&req)).await {
            Ok(Ok(resp)) if resp.status_code() == StatusCode::OK => break,
            Ok(_) | Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(10)).await;
            }
            other => panic!("could not occupy the connection permit: {other:?}"),
        }
    }

    // The permit is now held by `hold_client`'s still-open connection, so a fresh
    // connection must be rejected at the accept loop. Rejection surfaces either as
    // a clean early 503, or — because the server writes 503 and closes without
    // reading the request — as a TCP reset/abort on some platforms. Both are valid;
    // the one outcome that must NOT happen is a 200 OK (which would mean the limit
    // was not enforced).
    let client = make_client("127.0.0.1", sa.port());
    match timeout(Duration::from_secs(1), client.send(&req)).await {
        Ok(Ok(resp)) => {
            assert_eq!(
                resp.status_code(),
                StatusCode::SERVICE_UNAVAILABLE,
                "expected early 503 produced by server accept loop"
            );
            if let Some(v) = resp
                .get_header("Encapsulated")
                .and_then(|v| v.to_str().ok())
                .map(str::to_ascii_lowercase)
            {
                assert_eq!(v, "null-body=0");
            }
        }
        Ok(Err(Error::Io(e)))
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
            ) => {}
        Ok(Err(e)) => panic!("unexpected error from over-limit send: {e}"),
        Err(elapsed) => panic!("over-limit send timed out: {elapsed:?}"),
    }

    drop(hold_client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_found_404_for_unknown_service() {
    let (addr, _handle) = spawn_server_with_limit(16).await;
    let sa: SocketAddr = addr.parse().unwrap();
    let client = make_client("127.0.0.1", sa.port());

    let req = Request::reqmod("non-existent-service");
    let resp: ParsedResponse = timeout(Duration::from_secs(1), client.send(&req))
        .await
        .expect("client.send timed out")
        .expect("client.send failed");

    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    if let Some(v) = resp
        .get_header("Encapsulated")
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase)
    {
        assert_eq!(v, "null-body=0");
    }
}
