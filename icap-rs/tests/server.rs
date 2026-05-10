use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::Client;
use icap_rs::error::IcapResult;
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;

async fn always_204_handler(_req: Request) -> IcapResult<Response> {
    Response::no_content()
        .add_header("Server", "icap-rs/test")
        .try_set_istag("test")
}

async fn start_server_on(port: u16) {
    let respmod_opts = ServiceOptions::new()
        .with_service("Response Modifier")
        .with_options_ttl(60);

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_respmod("respmod", always_204_handler, Some(respmod_opts))
        .default_service("respmod")
        .alias("/", "respmod")
        .alias("alt", "respmod")
        .build()
        .await
        .expect("build server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
}

async fn start_reqmod_server_on(port: u16) {
    let reqmod_opts = ServiceOptions::new()
        .with_service("Request Modifier")
        .with_options_ttl(60)
        .add_allow("204");

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_reqmod("request", always_204_handler, Some(reqmod_opts))
        .build()
        .await
        .expect("build reqmod server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
}

async fn send_raw_icap_request(port: u16, request: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write raw ICAP request");
    stream.shutdown().await.expect("shutdown write side");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read raw ICAP response");

    Response::from_raw(&raw).expect("parse raw ICAP response")
}

fn make_embedded_http(body: &str) -> HttpResponse<Vec<u8>> {
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/plain")
        .header("Content-Length", body.len().to_string())
        .body(body.as_bytes().to_vec())
        .unwrap()
}

#[tokio::test]
async fn reqmod_null_body_reads_embedded_http_head() {
    let port = 13521;
    start_reqmod_server_on(port).await;

    let embedded = b"GET http://baidu.com/ HTTP/1.1\r\n\
User-Agent: curl/7.68.0\r\n\
Accept: */*\r\n\
Host: baidu.com\r\n\
\r\n";
    let headers = format!(
        "REQMOD icap://127.0.0.1:{port}/request ICAP/1.0\r\n\
Host: 127.0.0.1:{port}\r\n\
Encapsulated: req-hdr=0, null-body={}\r\n\
Allow: 204, trailers\r\n\
X-Client-IP: 10.3.12.1\r\n\
\r\n",
        embedded.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("write icap headers");
    tokio::time::sleep(Duration::from_millis(30)).await;
    stream
        .write_all(embedded)
        .await
        .expect("write embedded HTTP");

    let mut buf = vec![0; 1024];
    let n = stream.read(&mut buf).await.expect("read response");
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("ICAP/1.0 204 No Content"),
        "unexpected response: {response}"
    );
}

#[tokio::test]
async fn alias_and_default_service_resolve() {
    let port = 13520;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req_root = Request::respmod("")
        .allow_204()
        .with_http_response(make_embedded_http("hello"));
    let resp_root = client.send(&req_root).await.expect("icap send root");
    assert_eq!(resp_root.status_code, StatusCode::NO_CONTENT);

    let req_alt = Request::respmod("alt")
        .allow_204()
        .with_http_response(make_embedded_http("hello"));
    let resp_alt = client.send(&req_alt).await.expect("icap send alt");
    assert_eq!(resp_alt.status_code, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn respmod_no_allow_with_preview_may_be_204() {
    let port = 13512;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req = Request::respmod("respmod")
        .preview(0)
        .preview_ieof()
        .with_http_response(make_embedded_http("hello"));

    let resp = client.send(&req).await.expect("icap send");

    assert!(
        matches!(resp.status_code, StatusCode::NO_CONTENT | StatusCode::OK),
        "RFC: with Preview and no Allow, 204 is permitted (200 also ok). Got: {:?}",
        resp.status_code
    );
}

#[tokio::test]
async fn respmod_allow_present_may_be_204() {
    let port = 13513;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req = Request::respmod("respmod")
        .allow_204()
        .with_http_response(make_embedded_http("hello"));

    let resp = client.send(&req).await.expect("icap send");

    assert!(
        matches!(resp.status_code, StatusCode::NO_CONTENT | StatusCode::OK),
        "RFC: when Allow: 204 present, 204 is permitted (200 also ok). Got: {:?}",
        resp.status_code
    );
}

#[tokio::test]
async fn no_allow_header_must_be_200() {
    let port = 13511;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req = Request::respmod("respmod").with_http_response(make_embedded_http("hello"));

    let resp = client.send(&req).await.expect("icap send");

    assert_eq!(
        resp.status_code,
        StatusCode::OK,
        "RFC: MUST be 200 when no Allow: 204 and no Preview"
    );
}

#[tokio::test]
async fn unknown_method_returns_501_not_implemented() {
    let port = 13522;
    start_server_on(port).await;

    let resp = send_raw_icap_request(
        port,
        &format!(
            "FOO icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n"
        ),
    )
    .await;

    assert_eq!(resp.status_code, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.get_header("Connection").unwrap(), "close");
}

#[tokio::test]
async fn bad_version_returns_400_bad_request() {
    let port = 13523;
    start_server_on(port).await;

    let resp = send_raw_icap_request(
        port,
        &format!(
            "REQMOD icap://127.0.0.1:{port}/respmod ICAP/2.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n"
        ),
    )
    .await;

    assert_eq!(resp.status_code, StatusCode::BAD_REQUEST);
    assert_eq!(resp.get_header("Connection").unwrap(), "close");
}

#[tokio::test]
async fn missing_host_returns_400_bad_request() {
    let port = 13524;
    start_server_on(port).await;

    let resp = send_raw_icap_request(
        port,
        &format!(
            "REQMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
             Encapsulated: null-body=0\r\n\
             \r\n"
        ),
    )
    .await;

    assert_eq!(resp.status_code, StatusCode::BAD_REQUEST);
    assert_eq!(resp.get_header("Connection").unwrap(), "close");
}

#[tokio::test]
async fn invalid_encapsulated_returns_400_bad_request() {
    let port = 13525;
    start_server_on(port).await;

    let resp = send_raw_icap_request(
        port,
        &format!(
            "REQMOD icap://127.0.0.1:{port}/respmod ICAP/1.0\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Encapsulated: req-hdr=10, req-body=5\r\n\
             \r\n"
        ),
    )
    .await;

    assert_eq!(resp.status_code, StatusCode::BAD_REQUEST);
    assert_eq!(resp.get_header("Connection").unwrap(), "close");
}
