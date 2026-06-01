//! Example ICAPS server using PEM files from `test_data/certs`.
//! Build with TLS enabled (`--features tls-rustls`).

#[cfg(feature = "tls-rustls")]
use icap_rs::error::IcapResult;
#[cfg(feature = "tls-rustls")]
use icap_rs::server::options::ServiceOptions;
#[cfg(feature = "tls-rustls")]
use icap_rs::{Method, Request, Response, Server};

#[cfg(feature = "tls-rustls")]
const ISTAG: &str = "scan-1.0";

#[cfg(feature = "tls-rustls")]
#[tokio::main]
async fn main() -> IcapResult<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let server = Server::builder()
        .bind("0.0.0.0:13443")
        .with_tls_from_pem_files("test_data/certs/server.crt", "test_data/certs/server.key")
        .route(
            "scan",
            [Method::ReqMod, Method::RespMod],
            |_req: Request| async move { Response::no_content().try_set_istag(ISTAG) },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_preview(2048)
                    .add_allow("204"),
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

#[cfg(not(feature = "tls-rustls"))]
fn main() {
    eprintln!("This example requires feature `tls-rustls`.");
}
