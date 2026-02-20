use http::{Request as HttpRequest, Response as HttpResponse, Version};
use icap_rs::error::IcapResult;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{Client, Request, Response, Server, StatusCode};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;
use tokio::time::Duration;

const ISTAG: &str = "stream-writer-1";
const ECHO_BODY: &str = "streamed-body";

#[derive(Default)]
struct VecWriter {
    buf: Vec<u8>,
}

impl VecWriter {
    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl AsyncWrite for VecWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn start_server(port: u16) {
    let opts = ServiceOptions::new()
        .with_service("Streaming Writer Test")
        .add_allow("204");

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_reqmod(
            "scan",
            |_req: Request| async move {
                let http_resp = HttpResponse::builder()
                    .status(200)
                    .version(Version::HTTP_11)
                    .header("Content-Type", "text/plain")
                    .header("Content-Length", ECHO_BODY.len().to_string())
                    .body(ECHO_BODY.as_bytes().to_vec())
                    .unwrap();

                Response::new(StatusCode::OK, "OK")
                    .try_set_istag(ISTAG)?
                    .with_http_response(&http_resp)
            },
            Some(opts),
        )
        .build()
        .await
        .expect("build server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
}

#[tokio::test]
async fn streaming_response_is_forwarded_to_writer_and_not_buffered_in_response() -> IcapResult<()> {
    let port = 13531;
    start_server(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req_head = HttpRequest::builder()
        .method("POST")
        .uri("/upload")
        .version(Version::HTTP_11)
        .header("Host", "example.local")
        .header("Content-Length", "0")
        .body(())
        .unwrap();

    let req = Request::reqmod("scan")
        .preview(0)
        .preview_ieof()
        .with_http_request_head(req_head);

    let mut writer = VecWriter::default();
    let resp = client
        .send_streaming_reader_into_writer(&req, tokio::io::empty(), &mut writer)
        .await?;

    assert_eq!(resp.status_code, StatusCode::OK);
    assert!(resp.body.is_empty(), "response body must stay unbuffered");

    let payload = writer.into_inner();
    let s = String::from_utf8(payload).expect("utf8 payload");
    let s_lc = s.to_ascii_lowercase();
    assert!(s.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected payload: {s}");
    assert!(s_lc.contains("content-length: 13\r\n"), "missing content-length in payload: {s}");
    assert!(s.ends_with(ECHO_BODY), "payload tail mismatch: {s}");

    Ok(())
}
