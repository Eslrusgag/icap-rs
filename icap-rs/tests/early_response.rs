use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use icap_rs::client::Client;
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};

fn find_free_port() -> u16 {
    let sock = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = sock.local_addr().unwrap().port();
    port
}

async fn spawn_server_with_limit(limit: usize) -> (String, JoinHandle<()>) {
    let port = find_free_port();
    let addr = format!("127.0.0.1:{port}");

    let server = icap_rs::server::Server::builder()
        .bind(&addr)
        .with_max_connections(limit)
        .route_reqmod(
            "svc-options",
            |_: Request| async move {
                Ok(Response::new(StatusCode::OK, "OK")
                    .try_set_istag("x")
                    .unwrap())
            },
            None,
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

    let _hold = TcpStream::connect(&addr).await.expect("occupy permit");

    let sa: SocketAddr = addr.parse().unwrap();
    let client = make_client("127.0.0.1", sa.port());
    let req = Request::options("svc-options");

    let resp: Response = timeout(Duration::from_secs(1), client.send(&req))
        .await
        .expect("client.send timed out")
        .expect("client.send failed");

    assert_eq!(
        resp.status_code,
        StatusCode::SERVICE_UNAVAILABLE,
        "expected early 503 produced by server accept loop"
    );

    let enc = resp
        .get_header("Encapsulated")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());
    if let Some(v) = enc {
        assert_eq!(v, "null-body=0");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_found_404_for_unknown_service() {
    let (addr, _handle) = spawn_server_with_limit(16).await;
    let sa: SocketAddr = addr.parse().unwrap();
    let client = make_client("127.0.0.1", sa.port());

    let req = Request::reqmod("non-existent-service");
    let resp: Response = timeout(Duration::from_secs(1), client.send(&req))
        .await
        .expect("client.send timed out")
        .expect("client.send failed");

    assert_eq!(resp.status_code, StatusCode::NOT_FOUND);

    if let Some(v) = resp
        .get_header("Encapsulated")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
    {
        assert_eq!(v, "null-body=0");
    }
}
