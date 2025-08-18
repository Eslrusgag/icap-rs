use icap_rs::Client;
use icap_rs::HttpSession;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_session = HttpSession::new("POST", "/api/users")
        .add_header("Content-Type", "application/json")
        .add_header("User-Agent", "ICAP-Client/1.0")
        .with_body_string(r#"{"name": "John Doe", "email": "john@example.com"}"#);

    let client = Client::builder()
        .set_uri("icap://localhost:1344/test")
        .set_icap_method("REQMOD")
        .with_http_session(http_session)
        .build();

    println!("  Sending REQMOD request with HttpSession...\n {client:?}");
    match client.send().await {
        Ok(response) => {
            println!(
                "  Response received: {} {}",
                response.status_code, response.status_text
            );
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    Ok(())
}
