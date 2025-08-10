use icap_rs::{HttpMessage, IcapResponse, IcapServer, IcapStatusCode};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create server with all services
    let server = IcapServer::builder()
        .bind("127.0.0.1:1344")
        .add_service("echo", |request| async move {
            info!("Echo service called with method: {}", request.method);

            let response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
                .add_header("Content-Length", "0")
                .add_header("Server", "icap-rs/0.1.0");

            Ok(response)
        })
        .add_service("test", |request| async move {
            info!("Test service called with method: {}", request.method);

            let response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
                .add_header("Content-Length", "0")
                .add_header("Server", "icap-rs/0.1.0")
                .add_header("X-Request-Method", &request.method)
                .add_header("X-Request-URI", &request.uri);

            Ok(response)
        })
        .add_service("reqmod", |request| async move {
            info!("REQMOD service called with method: {}", request.method);

            // Check if this is a REQMOD request
            if request.method != "REQMOD" {
                let response =
                    IcapResponse::new(IcapStatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0");
                return Ok(response);
            }

            // Check if client allows 204 responses
            if request.can_return_204() {
                info!("Client allows 204 responses, checking if modification is needed");

                // Simulate checking if modification is needed
                // In a real implementation, you would analyze the HTTP request
                // and determine if any changes are required
                let needs_modification = false; // Example: no modification needed

                if !needs_modification {
                    info!("No modification needed, returning 204 No Content");
                    return Ok(IcapResponse::no_content().add_header("Server", "icap-rs/0.1.0"));
                }
            }

            // Get HTTP request data if available
            if let Some(http_request) = request.http_request {
                info!("Processing HTTP request: {}", http_request.start_line);
                info!("HTTP headers: {:?}", http_request.headers);

                // Add custom headers to the HTTP request
                let mut modified_headers = http_request.headers.clone();
                modified_headers.insert("X-ICAP-Processed".to_string(), "true".to_string());
                modified_headers.insert(
                    "X-ICAP-Server".to_string(),
                    "unified-icap-server".to_string(),
                );

                // Create modified HTTP request
                let _modified_request = HttpMessage {
                    start_line: http_request.start_line,
                    headers: modified_headers,
                    body: http_request.body,
                };

                let response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
                    .add_header("Content-Length", "0");

                Ok(response)
            } else {
                warn!("REQMOD request received but no HTTP request data found");
                let response = IcapResponse::new(IcapStatusCode::BadRequest400, "Bad Request")
                    .add_header("Content-Length", "0");
                Ok(response)
            }
        })
        .add_service("respmod", |request| async move {
            info!("RESPMOD service called with method: {}", request.method);

            // Check if this is a RESPMOD request
            if request.method != "RESPMOD" {
                let response =
                    IcapResponse::new(IcapStatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0");
                return Ok(response);
            }

            // Check if client allows 204 responses
            if request.can_return_204() {
                info!("Client allows 204 responses, checking if modification is needed");

                // Simulate checking if modification is needed
                // In a real implementation, you would analyze the HTTP response
                // and determine if any changes are required
                let needs_modification = false; // Example: no modification needed

                if !needs_modification {
                    info!("No modification needed, returning 204 No Content");
                    return Ok(IcapResponse::no_content().add_header("Server", "icap-rs/0.1.0"));
                }
            }

            // Get HTTP response data if available
            if let Some(http_response) = request.http_response {
                info!("Processing HTTP response: {}", http_response.start_line);
                info!("HTTP headers: {:?}", http_response.headers);

                // Add security headers to the HTTP response
                let mut modified_headers = http_response.headers.clone();
                modified_headers
                    .insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
                modified_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
                modified_headers
                    .insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
                modified_headers.insert("X-ICAP-Processed".to_string(), "true".to_string());
                modified_headers.insert(
                    "X-ICAP-Server".to_string(),
                    "unified-icap-server".to_string(),
                );

                // Create modified HTTP response
                let _modified_response = HttpMessage {
                    start_line: http_response.start_line,
                    headers: modified_headers,
                    body: http_response.body,
                };

                let response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
                    .add_header("Content-Length", "0");

                Ok(response)
            } else {
                warn!("RESPMOD request received but no HTTP response data found");
                let response = IcapResponse::new(IcapStatusCode::BadRequest400, "Bad Request")
                    .add_header("Content-Length", "0");
                Ok(response)
            }
        })
        .build()
        .await?;

    info!("Unified ICAP server started successfully!");
    info!("Available services: echo, test, reqmod, respmod");
    info!("Server listening on 127.0.0.1:1344");
    info!("Server supports 'Allow: 204' header for optimized responses");

    // Start the server
    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
