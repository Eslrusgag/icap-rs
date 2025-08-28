use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::Client;
use icap_rs::error::IcapResult;
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use tokio::time::Duration;

async fn always_204_handler(_req: Request) -> IcapResult<Response> {
    Ok(Response::no_content()
        .add_header("Server", "icap-rs/test")
        .try_set_istag("test")?)
}

async fn start_server_on(port: u16) {
    let respmod_opts = ServiceOptions::new()
        .with_service("Response Modifier")
        .with_options_ttl(60);

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .route_respmod("respmod", |req| always_204_handler(req), Some(respmod_opts))
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
async fn alias_and_default_service_resolve() {
    let port = 13520;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req_root = Request::respmod("")
        .allow_204()
        .with_http_response(make_embedded_http("hello"));
    let resp_root = client.send(&req_root).await.expect("icap send root");
    assert_eq!(resp_root.status_code, StatusCode::NoContent204);

    let req_alt = Request::respmod("alt")
        .allow_204()
        .with_http_response(make_embedded_http("hello"));
    let resp_alt = client.send(&req_alt).await.expect("icap send alt");
    assert_eq!(resp_alt.status_code, StatusCode::NoContent204);
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
        matches!(
            resp.status_code,
            StatusCode::NoContent204 | StatusCode::Ok200
        ),
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
        matches!(
            resp.status_code,
            StatusCode::NoContent204 | StatusCode::Ok200
        ),
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
        StatusCode::Ok200,
        "RFC: MUST be 200 when no Allow: 204 and no Preview"
    );
}
