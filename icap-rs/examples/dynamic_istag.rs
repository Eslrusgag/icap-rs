// Demonstrates how to rotate the ISTag at runtime using `IsTagHandle`.
//
// The handle is shared between `ServiceOptions` and route handlers via `Clone`.
// A background task simulates a periodic policy reload every 10 seconds.
//
// Inside the handler, `req.istag()` returns the tag that the server resolved
// from `ServiceOptions` before calling the handler — no extra Arc needed.
//
// Run with:  cargo run --example dynamic_istag
// Then send REQMOD to icap://127.0.0.1:1344/scan
// Watch the ISTag change in the server log every 10 s.

use std::time::Duration;

use icap_rs::request::IncomingRequest;
use icap_rs::response::Response;
use icap_rs::server::Server;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{HandlerError, HandlerResult, IsTagHandle};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let tag = IsTagHandle::new("policy-v1");

    // Background task: simulate a policy reload every 10 s.
    tokio::spawn({
        let tag = tag.clone();
        async move {
            let mut version = 1u64;
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                version += 1;
                let new_tag = format!("policy-v{version}");
                tag.set(&new_tag);
                info!("policy reloaded — ISTag is now: {new_tag}");
            }
        }
    });

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "scan",
            |req: IncomingRequest| async move { passthrough_204(req.istag().unwrap_or("")) },
            Some(
                ServiceOptions::new()
                    .with_dynamic_istag(tag)
                    .with_service("Dynamic ISTag demo")
                    .with_options_ttl(60)
                    .allow_204(),
            ),
        )
        .build()
        .await?;

    info!("ICAP server listening on icap://127.0.0.1:1344/scan");
    server.run().await?;
    Ok(())
}

fn passthrough_204(istag: &str) -> HandlerResult<Response> {
    Response::no_content_with_istag(istag).map_err(|e| HandlerError::internal(e.to_string()))
}
