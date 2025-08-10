use icap_rs::HttpSession;
use icap_rs::{IcapClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    println!("ICAP Client with HttpSession Example");
    println!("====================================");

    // Create HTTP session
    let http_session = HttpSession::new("POST", "/api/users")
        .add_header("Content-Type", "application/json")
        .add_header("User-Agent", "ICAP-Client/1.0")
        .with_body_string(r#"{"name": "John Doe", "email": "john@example.com"}"#);

    // Create ICAP client with the session
    let client = IcapClient::builder()
        .set_host("localhost")
        .set_port(1344)
        .set_service("reqmod")
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
