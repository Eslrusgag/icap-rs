use http::{Request as HttpRequest, Response as HttpResponse, Version};
use icap_rs::error::IcapResult;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{Client, IncomingRequest, Request, Response, Server, StatusCode};
use tokio::time::Duration;

const ISTAG: &str = "stream-writer-1";
const ECHO_BODY: &str = "streamed-body";

async fn start_server(port: u16) {
    let opts = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Streaming Writer Test")
        .add_allow("204");

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_reqmod(
            "scan",
            |_req: IncomingRequest| async move {
                let http_resp = HttpResponse::builder()
                    .status(200)
                    .version(Version::HTTP_11)
                    .header("Content-Type", "text/plain")
                    .header("Content-Length", ECHO_BODY.len().to_string())
                    .body(ECHO_BODY.as_bytes().to_vec())
                    .unwrap();

                Ok(Response::new(StatusCode::OK, "OK")
                    .try_set_istag(ISTAG)?
                    .with_http_response(&http_resp)?)
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
async fn streaming_response_is_buffered_in_response_body() -> IcapResult<()> {
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
        .with_http_request_head(req_head)?;

    let resp = client
        .send_streaming_reader(&req, tokio::io::empty())
        .await?;

    assert_eq!(resp.status_code(), StatusCode::OK);

    let text = String::from_utf8_lossy(resp.body());

    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected encapsulated HTTP response head, got:\n{text}"
    );

    assert!(
        text.to_ascii_lowercase()
            .contains("content-type: text/plain"),
        "expected Content-Type header, got:\n{text}"
    );

    assert!(
        text.to_ascii_lowercase().contains("content-length: 13"),
        "expected Content-Length header, got:\n{text}"
    );

    let sep = b"\r\n\r\n";

    let body_start = resp
        .body()
        .windows(sep.len())
        .position(|w| w == sep)
        .map(|pos| pos + sep.len())
        .expect("encapsulated HTTP response must contain header/body separator");

    assert_eq!(&resp.body()[body_start..], ECHO_BODY.as_bytes());

    Ok(())
}
