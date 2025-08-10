use clap::Parser;
use icap_rs::error::IcapResult;
use icap_rs::{HttpSession, IcapClient};
use std::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

#[derive(Parser, Debug)]
#[command(
    name = "rs-icap-client",
    about = "Rust ICAP client implementation",
    disable_version_flag = true,
    long_about = "A Rust implementation of ICAP client with similar interface to c-icap-client"
)]
struct Args {
    /// The ICAP server name
    #[arg(short = 'i', long, default_value = "localhost")]
    icap_servername: String,

    /// The server port
    #[arg(short = 'p', long, default_value = "1344")]
    port: u16,

    /// The service name
    #[arg(short = 's', long, default_value = "options")]
    service: String,
    /*
    /// Use TLS
    #[arg(long = "tls", action = clap::ArgAction::SetTrue)]
    tls: bool,

    /// Use TLS method
    #[arg(long = "tls-method")]
    tls_method: Option<String>,

    /// Disable server certificate verify
    #[arg(long = "tls-no-verify", action = clap::ArgAction::SetTrue)]
    tls_no_verify: bool,
     */
    /// Send this file to the ICAP server. Default is to send an options request
    #[arg(short = 'f', long)]
    filename: Option<String>,

    /// Save output to this file. Default is to send to stdout
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Use 'method' as method of the request modification
    #[arg(long = "method")]
    method: Option<String>,

    /// Send a request modification instead of response modification
    #[arg(long = "req")]
    req_url: Option<String>,

    /// Send a response modification request with request url the 'url'
    #[arg(long = "resp")]
    resp_url: Option<String>,

    /// Debug level info to stdout
    #[arg(short = 'd', long)]
    debug_level: Option<u8>,

    /// Do not send reshdr headers
    #[arg(long = "noreshdr", action = clap::ArgAction::SetTrue)]
    noreshdr: bool,

    /// Do not send preview data
    #[arg(long = "nopreview", action = clap::ArgAction::SetTrue)]
    nopreview: bool,

    /// Do not allow 204 outside preview
    #[arg(long = "no204", action = clap::ArgAction::SetTrue)]
    no204: bool,

    /// Support allow 206
    #[arg(long = "206", action = clap::ArgAction::SetTrue)]
    allow_206: bool,

    /// Include xheader in ICAP request headers
    #[arg(short = 'x', long)]
    xheader: Vec<String>,

    /// Include xheader in HTTP request headers
    #[arg(long = "hx")]
    hx_header: Vec<String>,

    /// Include xheader in HTTP response headers
    #[arg(long = "rhx")]
    rhx_header: Vec<String>,

    /// Sets the maximum preview data size
    #[arg(short = 'w', long)]
    preview_size: Option<usize>,

    /// Print response headers
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the generated ICAP request without sending it
    #[arg(long = "print-request", action = clap::ArgAction::SetTrue)]
    print_request: bool,
}

#[tokio::main]
async fn main() -> IcapResult<()> {
    let args = Args::parse();

    // Initialize logging based on debug level
    let debug_level = args.debug_level.unwrap_or(0);
    if debug_level > 0 {
        tracing_subscriber::fmt()
            .with_max_level(match debug_level {
                1 => tracing::Level::ERROR,
                2 => tracing::Level::WARN,
                3 => tracing::Level::INFO,
                4 => tracing::Level::DEBUG,
                _ => tracing::Level::TRACE,
            })
            .init();
    }

    info!("Starting rs-icap-client");
    debug!("Arguments: {:?}", args);

    // Determine ICAP method
    let icap_method = if let Some(method) = args.method {
        method.to_uppercase()
    } else if args.req_url.is_some() {
        "REQMOD".to_string()
    } else if args.resp_url.is_some() {
        "RESPMOD".to_string()
    } else if args.filename.is_some() {
        // If file is specified but no method, default to REQMOD
        "REQMOD".to_string()
    } else {
        "OPTIONS".to_string()
    };

    // Build ICAP headers
    let mut icap_headers = Vec::new();
    icap_headers.push("User-Agent: rs-icap-client/0.1.0".to_string());

    // Add preview size if specified and not disabled
    if !args.nopreview {
        if let Some(preview_size) = args.preview_size {
            icap_headers.push(format!("Preview: {}", preview_size));
        }
    }

    // Add allow headers
    if !args.no204 {
        icap_headers.push("Allow: 204".to_string());
    }
    if args.allow_206 {
        icap_headers.push("Allow: 206".to_string());
    }

    // Add custom ICAP headers
    for header in &args.xheader {
        icap_headers.push(header.clone());
    }

    let icap_headers_str = icap_headers.join("\r\n") + "\r\n";

    // Build HTTP session if needed
    let mut client_builder = IcapClient::builder()
        .set_host(&args.icap_servername)
        .set_port(args.port)
        .set_service(&args.service)
        .set_icap_method(&icap_method)
        .set_icap_headers(&icap_headers_str)
        .no_preview(args.nopreview);

    // Handle different request types
    if icap_method == "OPTIONS" {
        // Simple OPTIONS request - no HTTP session needed
        debug!("Sending OPTIONS request");
    } else {
        // REQMOD or RESPMOD request
        let mut http_session = if let Some(req_url) = &args.req_url {
            // REQMOD request
            debug!("Sending REQMOD request for URL: {}", req_url);
            HttpSession::new("GET", req_url)
        } else if let Some(resp_url) = &args.resp_url {
            // RESPMOD request
            debug!("Sending RESPMOD request for URL: {}", resp_url);
            HttpSession::new("GET", resp_url)
        } else if args.filename.is_some() {
            // Default HTTP session only if file is specified
            HttpSession::new("GET", "/rs-icap-client")
        } else {
            // No HTTP session for REQMOD/RESPMOD without file
            debug!("Sending {} request without HTTP session", icap_method);
            // Create empty session
            HttpSession::new("POST", "/rs-icap-client")
        };

        // Add HTTP headers
        for header in &args.hx_header {
            if let Some((name, value)) = header.split_once(':') {
                http_session = http_session.add_header(name.trim(), value.trim());
            }
        }

        // Add response headers for RESPMOD
        if icap_method == "RESPMOD" {
            for header in &args.rhx_header {
                if let Some((name, value)) = header.split_once(':') {
                    http_session = http_session.add_header(name.trim(), value.trim());
                }
            }
        }

        // Add body from file if specified
        if let Some(filename) = &args.filename {
            match fs::read_to_string(filename) {
                Ok(content) => {
                    http_session = http_session.with_body_string(&content);
                    debug!(
                        "Added file content to HTTP session: {} bytes",
                        content.len()
                    );
                }
                Err(e) => {
                    error!("Failed to read file {}: {}", filename, e);
                    return Err(e.into());
                }
            }
        }

        // Only add HTTP session if it has content or headers
        if !http_session.headers.is_empty()
            || !http_session.body.is_empty()
            || args.req_url.is_some()
            || args.resp_url.is_some()
            || args.filename.is_some()
        {
            client_builder = client_builder.with_http_session(http_session);
        }
    }

    // Build the client
    let client = client_builder.build();
    info!(
        "Sending {} request to {}:{}",
        icap_method, args.icap_servername, args.port
    );

    // Print request if requested
    if args.print_request {
        return match client.get_request() {
            Ok(request) => {
                println!("Generated ICAP request:");
                println!("{}", String::from_utf8_lossy(&request));
                Ok(())
            }
            Err(e) => {
                error!("Failed to generate request: {}", e);
                Err(e)
            }
        };
    }

    // Send the request
    match client.send().await {
        Ok(response) => {
            println!("ICAP/1.0 {} {}", response.status_code, response.status_text);
            for (name, value) in &response.headers {
                println!("{}: {}", name, value);
            }
            println!();

            if let Some(output_file) = &args.output {
                let mut file = File::create(output_file).await?;
                file.write_all(&response.body).await?;
                info!("Response body written to file: {}", output_file);
            }

            // Печать тела в консоль всегда (даже если пустое)
            print!("{}", String::from_utf8_lossy(&response.body));

            info!("Request completed successfully");
        }
        Err(e) => {
            error!("ICAP request failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
