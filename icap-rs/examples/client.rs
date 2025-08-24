use http::{Request as HttpRequest, Version};
use icap_rs::{Client, Request as IcapRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/api/users")
        .version(Version::HTTP_11)
        .header("Content-Type", "application/json")
        .header("User-Agent", "ICAP-Client/1.0")
        .body(r#"{"name":"John Doe","email":"john@example.com"}"#.as_bytes().to_vec())?;

    let client = Client::builder()
        .from_uri("icap://localhost:1344")?
        .keep_alive(true)
        .build();

    let req = IcapRequest::reqmod("/test")
        .icap_header("Allow", "204")
        .preview(1024)
        .with_http_request(http_req);

    println!("Sending REQMOD to icap://localhost:1344/test ...");

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
