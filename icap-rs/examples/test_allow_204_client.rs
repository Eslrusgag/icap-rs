use icap_rs::parser;
use icap_rs::{HttpMessage, HttpMessageTrait, IcapRequest, IcapResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let server_addr = "127.0.0.1:1344";

    // Test 1: REQMOD request with Allow: 204
    info!("=== Test 1: REQMOD with Allow: 204 ===");
    test_reqmod_with_allow_204(server_addr).await?;

    // Test 2: REQMOD request without Allow: 204
    info!("=== Test 2: REQMOD without Allow: 204 ===");
    test_reqmod_without_allow_204(server_addr).await?;

    // Test 3: RESPMOD request with Allow: 204
    info!("=== Test 3: RESPMOD with Allow: 204 ===");
    test_respmod_with_allow_204(server_addr).await?;

    // Test 4: Preview request (should allow 204 even without Allow: 204)
    info!("=== Test 4: Preview request ===");
    test_preview_request(server_addr).await?;

    Ok(())
}

async fn test_reqmod_with_allow_204(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(server_addr).await?;

    // Create HTTP request
    let http_request = HttpMessage::new("GET /api/data HTTP/1.1")
        .add_header("Host", "example.com")
        .add_header("User-Agent", "test-client/1.0")
        .add_header("Accept", "application/json");

    // Create ICAP request with Allow: 204
    let icap_request = IcapRequest::new("REQMOD", "icap://localhost/content-filter", "ICAP/1.0")
        .add_header("Host", "localhost:1344")
        .add_header("Allow", "204")
        .add_header("Content-Length", &http_request.to_raw().len().to_string())
        .with_http_request(http_request);

    // Send request
    let request_bytes = serialize_icap_request(&icap_request);
    stream.write_all(&request_bytes).await?;
    stream.flush().await?;

    // Read response
    let response = read_icap_response(&mut stream).await?;

    info!(
        "Response status: {} {}",
        response.status_code, response.status_text
    );
    info!("Response headers: {:?}", response.headers);

    if response.status_code.to_string() == "204" {
        info!("✓ Successfully received 204 No Content response");
    } else {
        info!("✗ Expected 204, got {}", response.status_code);
    }

    Ok(())
}

async fn test_reqmod_without_allow_204(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(server_addr).await?;

    // Create HTTP request
    let http_request = HttpMessage::new("GET /api/data HTTP/1.1")
        .add_header("Host", "example.com")
        .add_header("User-Agent", "test-client/1.0")
        .add_header("Accept", "application/json");

    // Create ICAP request without Allow: 204
    let icap_request = IcapRequest::new("REQMOD", "icap://localhost/content-filter", "ICAP/1.0")
        .add_header("Host", "localhost:1344")
        .add_header("Content-Length", &http_request.to_raw().len().to_string())
        .with_http_request(http_request);

    // Send request
    let request_bytes = serialize_icap_request(&icap_request);
    stream.write_all(&request_bytes).await?;
    stream.flush().await?;

    // Read response
    let response = read_icap_response(&mut stream).await?;

    info!(
        "Response status: {} {}",
        response.status_code, response.status_text
    );
    info!("Response headers: {:?}", response.headers);

    if response.status_code.to_string() == "200" {
        info!("✓ Successfully received 200 OK response (full message returned)");
    } else {
        info!("✗ Expected 200, got {}", response.status_code);
    }

    Ok(())
}

async fn test_respmod_with_allow_204(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(server_addr).await?;

    // Create HTTP response
    let http_response = HttpMessage::new("HTTP/1.1 200 OK")
        .add_header("Content-Type", "text/html")
        .add_header("Content-Length", "0")
        .with_body_string("<html><body>Hello World</body></html>");

    // Create ICAP request with Allow: 204
    let icap_request = IcapRequest::new("RESPMOD", "icap://localhost/content-filter", "ICAP/1.0")
        .add_header("Host", "localhost:1344")
        .add_header("Allow", "204")
        .add_header("Content-Length", &http_response.to_raw().len().to_string())
        .with_http_response(http_response);

    // Send request
    let request_bytes = serialize_icap_request(&icap_request);
    stream.write_all(&request_bytes).await?;
    stream.flush().await?;

    // Read response
    let response = read_icap_response(&mut stream).await?;

    info!(
        "Response status: {} {}",
        response.status_code, response.status_text
    );
    info!("Response headers: {:?}", response.headers);

    if response.status_code.to_string() == "204" {
        info!("✓ Successfully received 204 No Content response");
    } else {
        info!("✗ Expected 204, got {}", response.status_code);
    }

    Ok(())
}

async fn test_preview_request(
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(server_addr).await?;

    // Create HTTP request
    let http_request = HttpMessage::new("GET /api/data HTTP/1.1")
        .add_header("Host", "example.com")
        .add_header("User-Agent", "test-client/1.0")
        .add_header("Accept", "application/json");

    // Create ICAP request with Preview header (no Allow: 204)
    let icap_request = IcapRequest::new("REQMOD", "icap://localhost/content-filter", "ICAP/1.0")
        .add_header("Host", "localhost:1344")
        .add_header("Preview", "1024")
        .add_header("Content-Length", &http_request.to_raw().len().to_string())
        .with_http_request(http_request);

    // Send request
    let request_bytes = serialize_icap_request(&icap_request);
    stream.write_all(&request_bytes).await?;
    stream.flush().await?;

    // Read response
    let response = read_icap_response(&mut stream).await?;

    info!(
        "Response status: {} {}",
        response.status_code, response.status_text
    );
    info!("Response headers: {:?}", response.headers);

    if response.status_code.to_string() == "204" {
        info!("✓ Successfully received 204 No Content response for preview");
    } else {
        info!("✗ Expected 204 for preview, got {}", response.status_code);
    }

    Ok(())
}

fn serialize_icap_request(request: &IcapRequest) -> Vec<u8> {
    parser::serialize_icap_request(request)
}

async fn read_icap_response(
    stream: &mut TcpStream,
) -> Result<IcapResponse, Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = Vec::new();
    let mut temp_buffer = [0; 1024];

    // Read response data
    loop {
        match stream.read(&mut temp_buffer).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                buffer.extend_from_slice(&temp_buffer[..n]);

                // Check if we have a complete response
                if parser::is_complete_icap_response(&buffer) {
                    break;
                }
            }
            Err(e) => {
                error!("Error reading response: {}", e);
                return Err(e.into());
            }
        }
    }

    // Parse response
    IcapResponse::from_raw(&buffer)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}
