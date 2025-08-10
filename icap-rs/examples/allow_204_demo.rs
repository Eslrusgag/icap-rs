use icap_rs::{HttpMessage, HttpMessageTrait, IcapResponse, IcapServer, IcapStatusCode};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create server with Allow: 204 support
    let server = IcapServer::builder()
        .bind("127.0.0.1:1344")
        .add_service("content-filter", |request| async move {
            info!(
                "Content filter service called with method: {}",
                request.method
            );

            // Check if this is a REQMOD or RESPMOD request
            if !request.is_reqmod() && !request.is_respmod() {
                let response =
                    IcapResponse::new(IcapStatusCode::MethodNotAllowed405, "Method Not Allowed")
                        .add_header("Content-Length", "0");
                return Ok(response);
            }

            // Log Allow: 204 header information
            if request.allows_204() {
                info!("Client supports 204 No Content responses");
            } else {
                info!("Client does not support 204 No Content responses");
            }

            if request.is_preview() {
                info!("This is a preview request");
            }

            // Simulate content analysis
            let needs_modification = analyze_content(&request);

            // If client allows 204 and no modification is needed, return 204
            if request.can_return_204() && !needs_modification {
                info!("No modification needed, returning 204 No Content");
                return Ok(IcapResponse::no_content()
                    .add_header("Server", "icap-rs/0.1.0")
                    .add_header("X-ICAP-Status", "no-modification-needed"));
            }

            // If client doesn't allow 204, we must return the full message
            if !request.can_return_204() && !needs_modification {
                info!("Client doesn't allow 204, returning full unmodified message");
                return return_full_message(&request);
            }

            // If modification is needed, process the message
            if needs_modification {
                info!("Modification needed, processing message");
                return process_and_modify(&request);
            }

            // Fallback: return 200 OK with no content
            Ok(IcapResponse::new(IcapStatusCode::Ok200, "OK")
                .add_header("Content-Length", "0")
                .add_header("Server", "icap-rs/0.1.0"))
        })
        .build()
        .await?;

    info!("ICAP server with Allow: 204 support started!");
    info!("Service: content-filter");
    info!("Server listening on 127.0.0.1:1344");
    info!("Features:");
    info!("  - Supports 'Allow: 204' header");
    info!("  - Supports preview requests");
    info!("  - Returns 204 No Content when no modification is needed");
    info!("  - Returns full message when 204 is not allowed");

    // Start the server
    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}

/// Simulate content analysis to determine if modification is needed
fn analyze_content(request: &icap_rs::IcapRequest) -> bool {
    // In a real implementation, this would analyze the HTTP message content
    // For demo purposes, we'll use a simple heuristic

    if let Some(http_request) = &request.http_request {
        // Check if it's a GET request to a specific path
        if http_request.start_line.contains("GET /api/") {
            info!("API request detected - no modification needed");
            return false;
        }

        // Check for specific headers that might indicate sensitive content
        if let Some(content_type) = http_request.get_header("Content-Type") {
            if content_type.contains("application/json") {
                info!("JSON content detected - modification might be needed");
                return true;
            }
        }
    }

    if let Some(http_response) = &request.http_response {
        // Check response status
        if http_response.start_line.contains("200 OK") {
            info!("Successful response - checking content");

            // Check for specific content types
            if let Some(content_type) = http_response.get_header("Content-Type") {
                if content_type.contains("text/html") {
                    info!("HTML content detected - modification might be needed");
                    return true;
                }
            }
        }
    }

    // Default: no modification needed
    info!("No specific content patterns detected - no modification needed");
    false
}

/// Return the full unmodified message when 204 is not allowed
fn return_full_message(
    request: &icap_rs::IcapRequest,
) -> Result<IcapResponse, icap_rs::error::IcapError> {
    let mut response = IcapResponse::new(IcapStatusCode::Ok200, "OK");

    if let Some(http_request) = &request.http_request {
        // Return the original HTTP request
        let modified_request = HttpMessage {
            start_line: http_request.start_line.clone(),
            headers: http_request.headers.clone(),
            body: http_request.body.clone(),
        };

        // In a real implementation, you would serialize the HTTP message
        // and include it in the response body
        response = response
            .add_header(
                "Content-Length",
                &modified_request.to_raw().len().to_string(),
            )
            .add_header("Server", "icap-rs/0.1.0")
            .add_header("X-ICAP-Status", "unmodified-returned");
    } else if let Some(http_response) = &request.http_response {
        // Return the original HTTP response
        let modified_response = HttpMessage {
            start_line: http_response.start_line.clone(),
            headers: http_response.headers.clone(),
            body: http_response.body.clone(),
        };

        response = response
            .add_header(
                "Content-Length",
                &modified_response.to_raw().len().to_string(),
            )
            .add_header("Server", "icap-rs/0.1.0")
            .add_header("X-ICAP-Status", "unmodified-returned");
    }

    Ok(response)
}

/// Process and modify the message
fn process_and_modify(
    request: &icap_rs::IcapRequest,
) -> Result<IcapResponse, icap_rs::error::IcapError> {
    let mut response = IcapResponse::new(IcapStatusCode::Ok200, "OK");

    if let Some(http_request) = &request.http_request {
        // Add security headers to the request
        let mut modified_headers = http_request.headers.clone();
        modified_headers.insert("X-ICAP-Processed".to_string(), "true".to_string());
        modified_headers.insert(
            "X-Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        );

        let modified_request = HttpMessage {
            start_line: http_request.start_line.clone(),
            headers: modified_headers,
            body: http_request.body.clone(),
        };

        response = response
            .add_header(
                "Content-Length",
                &modified_request.to_raw().len().to_string(),
            )
            .add_header("Server", "icap-rs/0.1.0")
            .add_header("X-ICAP-Status", "modified");
    } else if let Some(http_response) = &request.http_response {
        // Add security headers to the response
        let mut modified_headers = http_response.headers.clone();
        modified_headers.insert("X-ICAP-Processed".to_string(), "true".to_string());
        modified_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        modified_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        modified_headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());

        let modified_response = HttpMessage {
            start_line: http_response.start_line.clone(),
            headers: modified_headers,
            body: http_response.body.clone(),
        };

        response = response
            .add_header(
                "Content-Length",
                &modified_response.to_raw().len().to_string(),
            )
            .add_header("Server", "icap-rs/0.1.0")
            .add_header("X-ICAP-Status", "modified");
    }

    Ok(response)
}
