use icap_rs::Client;
use icap_rs::error::IcapResult;
use icap_rs::options::{IcapMethod, OptionsConfig};
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;

use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use tokio::time::{Duration, sleep};

async fn always_204_handler(_req: Request) -> IcapResult<Response> {
    Ok(Response::no_content().add_header("Server", "icap-rs/test"))
}

async fn start_server_on(port: u16) {
    let respmod_opts = OptionsConfig::new(vec![IcapMethod::RespMod], "respmod-1.0")
        .with_service("Response Modifier")
        .with_options_ttl(60);

    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .add_service("respmod", |req: Request| async move {
            always_204_handler(req).await
        })
        .add_options_config("respmod", respmod_opts)
        .build()
        .await
        .expect("build server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    sleep(Duration::from_millis(60)).await;
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
#[ignore]
async fn respmod_no_allow_must_be_200() {
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

#[tokio::test]
async fn respmod_no_allow_with_preview_may_be_204() {
    let port = 13512;
    start_server_on(port).await;

    let client = Client::builder().host("127.0.0.1").port(port).build();

    let req = Request::respmod("respmod")
        .allow_204(false)
        .preview(0) // отправляем Preview
        .preview_ieof(true)
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
        .allow_204(true) // разрешаем 204
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
