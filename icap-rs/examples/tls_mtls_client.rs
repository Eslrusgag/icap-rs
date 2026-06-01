//! Example mutual-TLS (mTLS) ICAPS client.
//!
//! Run with `--features tls-rustls`. Presents the bundled test client cert
//! (`test_data/certs/client.{crt,key}`) and trusts the test CA. Pair with a
//! server that calls
//! [`icap_rs::tls::ServerTlsConfig::with_client_auth_pem_file`].

use icap_rs::tls::ClientTlsConfig;
use icap_rs::{Client, Request as IcapRequest};

const URI: &str = "icaps://localhost:13443/scan";
const CA_PEM: &str = "test_data/certs/ca.pem";
const CLIENT_CERT: &str = "test_data/certs/client.crt";
const CLIENT_KEY: &str = "test_data/certs/client.key";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls = ClientTlsConfig::with_native_roots()
        .add_root_ca_pem_file(CA_PEM)?
        .with_client_auth_pem_files(CLIENT_CERT, CLIENT_KEY)?
        .with_sni("localhost");

    let client = Client::builder().with_uri(URI)?.with_tls(tls).build();

    let resp = client.send(&IcapRequest::options("scan")).await?;
    println!(
        "OPTIONS → {} {}",
        resp.status_code().as_u16(),
        resp.status_text()
    );

    Ok(())
}
