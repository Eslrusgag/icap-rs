//! Example ICAPS server using PEM files from `test_data/certs`.
//! Build with TLS enabled (`--features tls-rustls`).

use icap_rs::error::IcapResult;
use icap_rs::server::options::ServiceOptions;
use icap_rs::tls::ServerTlsConfig;
use icap_rs::{IncomingRequest, Method, Response, Server};

const ISTAG: &str = "scan-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let tls = ServerTlsConfig::from_pem_files(
        "test_data/certs/server.crt",
        "test_data/certs/server.key",
    )?;

    let server = Server::builder()
        .bind("0.0.0.0:13443")
        .with_tls(tls)
        .route(
            "scan",
            [Method::ReqMod, Method::RespMod],
            |_req: IncomingRequest| async move { Response::no_content_with_istag(ISTAG) },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_preview(2048)
                    .allow_204(),
            ),
        )
        .default_service("scan")
        .alias("/", "scan")
        .alias("/test", "scan")
        .with_max_connections(128)
        .build()
        .await?;

    server.run().await
}
