use icap_rs::error::{Error, IcapResult};
use icap_rs::response::StatusCode as IcapStatus;
use icap_rs::{Client, Request};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub fn options_200_wire() -> &'static [u8] {
    b"ICAP/1.0 200 OK\r\n\
      ISTag: x\r\n\
      Encapsulated: null-body=0\r\n\
      \r\n"
}

async fn read_until_double_crlf(sock: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    Ok(())
}

pub async fn spawn_slow_icap_server(
    delay_ms: u64,
    wire: &'static [u8],
) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let h: JoinHandle<()> = tokio::spawn(async move {
        if let Ok((mut sock, _peer)) = listener.accept().await {
            let _ = read_until_double_crlf(&mut sock).await;

            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let _ = sock.write_all(wire).await;
            let _ = sock.flush().await;

            let _ = sock.shutdown().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    (addr, h)
}

async fn do_options_once(
    uri: &str,
    timeout_secs: Option<u64>,
) -> IcapResult<icap_rs::response::Response> {
    let client = Client::builder()
        .from_uri(uri)?
        .read_timeout(timeout_secs.map(Duration::from_secs))
        .build();
    let req = Request::options("/");
    client.send(&req).await
}

#[tokio::test]
async fn timeout_fires_when_server_is_too_slow() {
    let (addr, _h) = spawn_slow_icap_server(1500, options_200_wire()).await;
    let uri = format!("icap://{}:{}/", addr.ip(), addr.port());

    let started = std::time::Instant::now();
    let res = do_options_once(&uri, Some(1)).await;
    let elapsed = started.elapsed();

    match res {
        Err(Error::ClientTimeout(d)) => {
            assert_eq!(d.as_secs(), 1);
            assert!(
                elapsed >= Duration::from_millis(900),
                "returned too fast: {:?}",
                elapsed
            );
        }
        other => panic!("expected timeout error, got: {:?}", other),
    }
}

#[tokio::test]
async fn no_timeout_allows_fast_server() {
    let (addr, _h) = spawn_slow_icap_server(100, options_200_wire()).await;
    let uri = format!("icap://{}:{}/", addr.ip(), addr.port());

    let res = do_options_once(&uri, None).await;
    assert!(
        res.is_ok(),
        "expected success without timeout, got: {:?}",
        res.err()
    );
    let resp = res.unwrap();
    assert!(matches!(resp.status_code, IcapStatus::OK));
}

#[tokio::test]
async fn small_timeout_but_server_responds_in_time() {
    let (addr, _h) = spawn_slow_icap_server(100, options_200_wire()).await;
    let uri = format!("icap://{}:{}/", addr.ip(), addr.port());

    let res = do_options_once(&uri, Some(2)).await;
    assert!(
        res.is_ok(),
        "expected success within timeout, got: {:?}",
        res.err()
    );
    let resp = res.unwrap();
    assert!(matches!(resp.status_code, IcapStatus::OK));
}
