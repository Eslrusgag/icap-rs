use icap_rs::server::options::ServiceOptions;
use icap_rs::{Body, EmbeddedHttp, PreviewDecision, Request, Response, Server};
use tracing::{info, warn};

const ISTAG: &str = "preview-decision-1.0";

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "scan",
            |request: Request| async move {
                match embedded_body(&request) {
                    Some(Body::Preview { bytes, .. }) => {
                        info!("REQMOD preview handler called, preview_len={}", bytes.len());

                        if bytes.windows(b"BLOCK".len()).any(|w| w == b"BLOCK") {
                            warn!("blocking request from preview bytes without 100 Continue");
                            return Ok(PreviewDecision::Respond(
                                Response::no_content().try_set_istag(ISTAG)?,
                            ));
                        }

                        Ok(PreviewDecision::Continue)
                    }
                    Some(Body::Full { reader }) => {
                        info!(
                            "REQMOD full handler called after preview continuation, body_len={}",
                            reader.len()
                        );
                        Ok(PreviewDecision::Respond(
                            Response::no_content().try_set_istag(ISTAG)?,
                        ))
                    }
                    _ => Ok(PreviewDecision::Respond(
                        Response::no_content().try_set_istag(ISTAG)?,
                    )),
                }
            },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("Preview decision scanner")
                    .with_preview(1024)
                    .add_allow("204"),
            ),
        )
        .build()
        .await?;

    info!("preview decision ICAP server listening on 127.0.0.1:1344, service=scan");
    server.run().await
}

const fn embedded_body(request: &Request) -> Option<&Body<Vec<u8>>> {
    match &request.embedded {
        Some(EmbeddedHttp::Req { body, .. } | EmbeddedHttp::Resp { body, .. }) => Some(body),
        None => None,
    }
}
