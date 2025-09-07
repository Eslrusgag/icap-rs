use std::env;

use http::{Request as HttpRequest, Version};
use icap_rs::{Client, Request as IcapRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let uri = env::args()
        .nth(1)
        .unwrap_or_else(|| "icaps://localhost:1344".to_string());

    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/api/users")
        .version(Version::HTTP_11)
        .header("Content-Type", "application/json")
        .header("User-Agent", "ICAP-Client/1.0")
        .body(r#"{"name":"John Doe","email":"john@example.com"}"#.as_bytes().to_vec())?;

    let mut builder = Client::builder()
        .from_uri(&uri)?
        .keep_alive(true)
        .user_agent("ICAP-Client/1.0");

    // Для локальной отладки можно отключить проверку сертификата:
    if env::var("ICAP_TLS_INSECURE").is_ok() {
        builder = builder.danger_disable_cert_verify(true);
    }

    if let Ok(sni) = env::var("ICAP_SNI") {
        builder = builder.sni_hostname(&sni);
    }

    #[cfg(all(feature = "tls-rustls", feature = "tls-openssl"))]
    {
        match env::var("ICAP_TLS_BACKEND").as_deref() {
            Ok("rustls") => {
                builder = builder.use_rustls();
            }
            Ok("openssl") => {
                builder = builder.use_openssl();
            }
            _ => { /* авто */ }
        }
    }

    let client = builder.build();

    let req = IcapRequest::reqmod("/test")
        .icap_header("Allow", "204")
        .preview(1024)
        .with_http_request(http_req);

    println!("Sending REQMOD to {uri} ...");

    match client.send(&req).await {
        Ok(resp) => {
            println!("ICAP {} {}", resp.status_code, resp.status_text);
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
