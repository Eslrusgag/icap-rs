//! Example ICAPS server using PEM files from `test_data/certs`.
//! Build with TLS enabled (default features include `tls-rustls-ring`).

use icap_rs::error::IcapResult;
use icap_rs::server::options::ServiceOptions;
use icap_rs::{Method, Request, Response, Server};

const ISTAG: &str = "scan-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Server listens on 13443 (ICAPS). Service is "scan".
    let server = Server::builder()
        .bind("0.0.0.0:13443")
        // Choose ONE of the two lines below:
        // (1) Plain TLS (no client-auth):
        .with_tls_from_pem_files("test_data/certs/server.crt", "test_data/certs/server.key")
        // (2) mTLS (require client cert) — uncomment and comment-out the line above:
        // .with_mtls_from_pem_files(
        //     "test_data/certs/server.crt",
        //     "test_data/certs/server.key",
        //     "test_data/certs/ca.pem",
        // )
        .route(
            "scan",
            [Method::ReqMod, Method::RespMod],
            |_req: Request| async move { Ok(Response::no_content().try_set_istag(ISTAG)?) },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_preview(2048)
                    .add_allow("204"),
            ),
        )
        .default_service("scan")
        .alias("/", "scan")
        .alias("/test", "scan") // for clients that call /test
        .with_max_connections(128)
        .build()
        .await?;

    server.run().await
}
