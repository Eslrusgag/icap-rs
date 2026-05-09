use icap_rs::{Client, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

async fn read_one_icap_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0; 1024];

    loop {
        let n = stream.read(&mut tmp).await.expect("read request");
        assert!(n > 0, "client closed before complete ICAP headers");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return buf;
        }
    }
}

#[tokio::test]
async fn keep_alive_reuses_single_connection_for_multiple_requests() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept one connection");

        for _ in 0..2 {
            let request = read_one_icap_head(&mut stream).await;
            assert!(
                request.starts_with(b"OPTIONS "),
                "unexpected request: {}",
                String::from_utf8_lossy(&request)
            );

            stream
                .write_all(
                    b"ICAP/1.0 200 OK\r\n\
ISTag: keepalive-test\r\n\
Encapsulated: null-body=0\r\n\
\r\n",
                )
                .await
                .expect("write response");
        }
    });

    let client = Client::builder()
        .host("127.0.0.1")
        .port(addr.port())
        .keep_alive(true)
        .build();
    let req = Request::options("svc");

    let first = timeout(Duration::from_secs(1), client.send(&req))
        .await
        .expect("first request timed out")
        .expect("first request failed");
    assert_eq!(first.status_code, StatusCode::OK);

    let second = timeout(Duration::from_secs(1), client.send(&req))
        .await
        .expect("second request timed out")
        .expect("second request failed");
    assert_eq!(second.status_code, StatusCode::OK);

    server.await.expect("fake server task failed");
}
