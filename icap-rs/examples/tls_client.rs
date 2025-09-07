use http::{Request as HttpRequest, Version};
use icap_rs::{Client, Request as IcapRequest};

const URI: &str = "icaps://localhost:13443/scan"; // ICAPS endpoint + service
const SNI: &str = "localhost"; // Must match server certificate
const CA_PEM_PATH: &str = "test_data/certs/ca.pem"; // Test CA that signed server.crt

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embedded HTTP request that will be sent inside ICAP REQMOD
    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/api/users")
        .version(Version::HTTP_11)
        .header("Content-Type", "application/json")
        .header("User-Agent", "ICAP-Client/1.0")
        .body(r#"{"name":"John Doe","email":"john@example.com"}"#.as_bytes().to_vec())?;

    // Build ICAP client with explicit settings
    let mut builder = Client::builder()
        .with_uri(URI)?
        .keep_alive(true)
        .user_agent("ICAP-Client/1.0")
        .sni_hostname(SNI);

    // Trust our test CA explicitly (preferred for self-signed test setup)
    #[cfg(feature = "tls-rustls")]
    {
        builder = builder.add_root_ca_pem_file(CA_PEM_PATH)?;
    }

    // If the build does not include the rustls backend (unlikely in these examples),
    // you can fallback to disabling verification for local tests. Commented out by default.
    // builder = builder.danger_disable_cert_verify(true);

    let client = builder.build();

    // Prepare ICAP REQMOD for the /scan service
    let req = IcapRequest::reqmod("/scan")
        .icap_header("Allow", "204")
        .preview(1024)
        .with_http_request(http_req);

    println!("Sending REQMOD to {URI} ...");

    match client.send(&req).await {
        Ok(resp) => {
            println!("ICAP {} {}", resp.status_code.as_u16(), resp.status_text);
            for (name, value) in resp.headers().iter() {
                println!("{}: {}", name, value.to_str().unwrap_or_default());
            }
            if !resp.body.is_empty() {
                println!("\nBody ({} bytes):", resp.body.len());
                println!("{}", String::from_utf8_lossy(&resp.body));
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
        }
    }

    Ok(())
}
