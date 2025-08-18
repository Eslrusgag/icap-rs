use clap::Parser;
use icap_rs::Client;
use icap_rs::client::Request;
use icap_rs::error::IcapResult;
use icap_rs::http::HttpMessage;
use std::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "rs-icap-client",
    about = "Rust ICAP client implementation",
    disable_version_flag = true,
    long_about = "A Rust implementation of ICAP client with a c-icap-client-like CLI"
)]
struct Args {
    /// Full ICAP URI like icap://host[:port]/service)
    #[arg(short = 'u', long, default_value = "icap://127.0.0.1:1344/")]
    uri: String,

    /// Send this file to the ICAP server (implies REQMOD if method not set)
    #[arg(short = 'f', long)]
    filename: Option<String>,

    /// Save ICAP response body to file (default: stdout)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// ICAP method: OPTIONS|REQMOD|RESPMOD
    #[arg(long = "method")]
    method: Option<String>,

    /// Send REQMOD with given request URL
    #[arg(long = "req")]
    req_url: Option<String>,

    /// Send RESPMOD with given request URL (we’ll encapsulate HTTP info)
    #[arg(long = "resp")]
    resp_url: Option<String>,

    /// Debug level info to stdout
    #[arg(short = 'd', long)]
    debug_level: Option<u8>,

    /// Do not send HTTP response headers (compat; no-op here)
    #[arg(long = "noreshdr", action = clap::ArgAction::SetTrue)]
    noreshdr: bool,

    /// Do not send Preview at all (overrides --preview-size and -x Preview)
    #[arg(long = "nopreview", action = clap::ArgAction::SetTrue)]
    nopreview: bool,

    /// Do not allow 204 outside preview
    #[arg(long = "no204", action = clap::ArgAction::SetTrue)]
    no204: bool,

    /// Support allow 206
    #[arg(long = "206", action = clap::ArgAction::SetTrue)]
    allow_206: bool,

    /// Extra ICAP headers (repeatable): -x "Header: Value"
    #[arg(short = 'x', long)]
    xheader: Vec<String>,

    /// Extra HTTP request headers (repeatable): --hx "Header: Value"
    #[arg(long = "hx")]
    hx_header: Vec<String>,

    /// Extra HTTP response headers (repeatable): --rhx "Header: Value"
    #[arg(long = "rhx")]
    rhx_header: Vec<String>,

    /// Preview size (sets `Preview: N`) unless --nopreview
    #[arg(short = 'w', long)]
    preview_size: Option<usize>,

    /// Print ICAP response headers
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the generated ICAP request summary without sending it
    #[arg(long = "print-request", action = clap::ArgAction::SetTrue)]
    print_request: bool,
}

#[tokio::main]
async fn main() -> IcapResult<()> {
    let args = Args::parse();

    // logging
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

    let icap_method = if let Some(m) = args.method {
        m.to_uppercase()
    } else if args.req_url.is_some() {
        "REQMOD".to_string()
    } else if args.resp_url.is_some() {
        "RESPMOD".to_string()
    } else if args.filename.is_some() {
        "REQMOD".to_string()
    } else {
        "OPTIONS".to_string()
    };

    // В новой архитектуре клиент НИЧЕГО сам не добавляет про Preview.
    let client = Client::from_uri(&args.uri)?;

    let service = service_from_uri(&args.uri).unwrap_or_else(|| "/options".to_string());

    // Сборка Request
    let mut req_parts = Request::new(&icap_method, &service);

    if !args.no204 {
        req_parts = req_parts.allow_204(true);
    }
    if args.allow_206 {
        req_parts = req_parts.allow_206(true);
    }

    // Сначала обработаем дополнительные ICAP-заголовки (-x).
    // Если включён --nopreview, то принудительно игнорируем любые попытки задать Preview через -x.
    for h in &args.xheader {
        if let Some((k, v)) = h.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("Preview") {
                if args.nopreview {
                    warn!("--nopreview is set: skipping header '{}: {}'", key, val);
                    continue;
                }
                // Request::header маппит Preview -> preview_size
                req_parts = req_parts.header(key, val);
            } else {
                req_parts = req_parts.header(key, val);
            }
        } else {
            warn!("Bad -x header format (use \"Name: Value\"): '{}'", h);
        }
    }

    // Затем CLI-параметр превью. Если --nopreview, игнорируем.
    if !args.nopreview {
        if let Some(n) = args.preview_size {
            req_parts = req_parts.preview(n);
        }
    } else if args.preview_size.is_some() {
        warn!("--nopreview overrides --preview-size, Preview will not be sent");
    }

    // Вложенный HTTP только для REQMOD/RESPMOD
    if icap_method == "REQMOD" || icap_method == "RESPMOD" {
        let mut http = if let Some(req_url) = &args.req_url {
            HttpMessage::builder(&format!("GET {} HTTP/1.1", req_url))
                .header("Host", host_from_url(req_url).unwrap_or("example.com"))
                .build()
        } else if let Some(resp_url) = &args.resp_url {
            // Упрощённая заглушка HTTP-ответа
            HttpMessage::builder("HTTP/1.1 200 OK")
                .header("Content-Type", "application/octet-stream")
                .header("X-Resp-Source", resp_url)
                .build()
        } else if args.filename.is_some() {
            HttpMessage::builder("GET /rs-icap-client HTTP/1.1")
                .header("Host", "localhost")
                .build()
        } else {
            HttpMessage::builder("POST /rs-icap-client HTTP/1.1")
                .header("Host", "localhost")
                .build()
        };

        for h in &args.hx_header {
            if let Some((k, v)) = h.split_once(':') {
                http = http.add_header(k.trim(), v.trim());
            } else {
                warn!("Bad --hx header format (use \"Name: Value\"): '{}'", h);
            }
        }
        if icap_method == "RESPMOD" {
            for h in &args.rhx_header {
                if let Some((k, v)) = h.split_once(':') {
                    http = http.add_header(k.trim(), v.trim());
                } else {
                    warn!("Bad --rhx header format (use \"Name: Value\"): '{}'", h);
                }
            }
        }

        if let Some(filename) = &args.filename {
            match fs::read(filename) {
                Ok(bytes) => {
                    http = http.with_body(&bytes);
                    debug!("Added file content to HTTP: {} bytes", bytes.len());
                }
                Err(e) => {
                    error!("Failed to read file {}: {}", filename, e);
                    return Err(e.into());
                }
            }
        }

        req_parts = req_parts.http(http);
    } else {
        debug!("Sending OPTIONS request");
    }

    info!("Sending {} to {}", icap_method, args.uri);

    // Печать сформированного запроса (без отправки)
    if args.print_request {
        return match client.get_request(&req_parts) {
            Ok(bytes) => {
                // ВНИМАНИЕ: это может содержать бинарные данные тела — печать «как есть» только для отладки
                println!("{}", String::from_utf8_lossy(&bytes));
                Ok(())
            }
            Err(e) => {
                error!("Failed to generate request: {}", e);
                Err(e)
            }
        };
    }

    // Отправка
    match client.send(&req_parts).await {
        Ok(response) => {
            println!("ICAP/1.0 {} {}", response.status_code, response.status_text);
            if args.verbose {
                for (name, value) in &response.headers {
                    println!("{}: {}", name, value);
                }
                println!();
            }

            if let Some(output_file) = &args.output {
                let mut file = File::create(output_file).await?;
                file.write_all(&response.body).await?;
                info!("Response body written to file: {}", output_file);
            } else {
                print!("{}", String::from_utf8_lossy(&response.body));
            }

            info!("Request completed successfully");
        }
        Err(e) => {
            error!("ICAP request failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

fn service_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("icap://")?;
    let slash = rest.find('/')?;
    Some(rest[slash..].to_string()) // включает ведущий '/'
}

fn host_from_url(url: &str) -> Option<&str> {
    if let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    {
        return rest.split('/').next();
    }
    None
}
