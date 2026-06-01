use http::{Request as HttpRequest, Version};
use icap_rs::{Client, Request as IcapRequest};
use std::path::PathBuf;
use tokio::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from("Cargo.toml"), PathBuf::from);
    let file_len = tokio::fs::metadata(&file_path).await?.len();

    let http_head = HttpRequest::builder()
        .method("POST")
        .uri("/upload")
        .version(Version::HTTP_11)
        .header("Host", "origin.example")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", file_len.to_string())
        .body(())?;

    let client = Client::builder()
        .with_uri("icap://localhost:1344")?
        .keep_alive(true)
        .build();

    let req = IcapRequest::reqmod("/scan")
        .allow_204()
        .preview(1024)
        .with_http_request_head(http_head)?;

    println!(
        "Streaming {} bytes from {} to icap://localhost:1344/scan ...",
        file_len,
        file_path.display()
    );

    let file = File::open(&file_path).await?;
    let resp = client.send_streaming_reader(&req, file).await?;

    println!("ICAP {} {}", resp.status_code(), resp.status_text());
    for (name, value) in resp.headers() {
        println!("{}: {}", name, value.to_str().unwrap_or_default());
    }
    if !resp.body().is_empty() {
        println!("\nBody ({} bytes):", resp.body().len());
        println!("{}", String::from_utf8_lossy(resp.body()));
    }

    Ok(())
}
