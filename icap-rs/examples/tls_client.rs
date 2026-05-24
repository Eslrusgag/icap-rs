//! Example ICAPS client using the new `ClientTlsConfig` builder.
//!
//! Run with `--features tls-rustls`. The example trusts the bundled test CA
//! (`test_data/certs/ca.pem`) so it works against `examples/tls_server.rs`
//! out of the box.

use http::{Request as HttpRequest, Version};
use icap_rs::tls::ClientTlsConfig;
use icap_rs::{Client, Request as IcapRequest};

const URI: &str = "icaps://localhost:13443/scan";
const CA_PEM_PATH: &str = "test_data/certs/ca.pem";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/api/users")
        .version(Version::HTTP_11)
        .header("Content-Type", "application/json")
        .header("User-Agent", "ICAP-Client/1.0")
        .body(r#"{"name":"John Doe","email":"john@example.com"}"#.as_bytes().to_vec())?;

    let tls = ClientTlsConfig::with_native_roots()
        .add_root_ca_pem(CA_PEM_PATH)?
        .with_sni("localhost");

    let client = Client::builder()
        .with_uri(URI)?
        .keep_alive(true)
        .user_agent("ICAP-Client/1.0")
        .with_tls(tls)
        .build();

    let req = IcapRequest::reqmod("/scan")
        .icap_header("Allow", "204")
        .preview(1024)
        .with_http_request(http_req)?;

    println!("Sending REQMOD to {URI} ...");

    match client.send(&req).await {
        Ok(resp) => {
            println!(
                "ICAP {} {}",
                resp.status_code().as_u16(),
                resp.status_text()
            );
            for (name, value) in resp.headers() {
                println!("{}: {}", name, value.to_str().unwrap_or_default());
            }
            if !resp.body().is_empty() {
                println!("\nBody ({} bytes):", resp.body().len());
                println!("{}", String::from_utf8_lossy(resp.body()));
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }

    Ok(())
}
