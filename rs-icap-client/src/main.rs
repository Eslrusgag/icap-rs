use clap::Parser;
use http::{
    HeaderName, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse, StatusCode,
    Version,
};
use icap_rs::client::{Client, Request};
use icap_rs::error::IcapResult;
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
    /// Full ICAP URI like icap://host[:port]/service
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

    /// Send REQMOD with given request URL (origin-form or absolute URI)
    #[arg(long = "req")]
    req_url: Option<String>,

    /// Send RESPMOD with given request URL (we’ll put it into a header for trace)
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

    /// Print the generated ICAP request (raw wire) without sending it
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

    let icap_method = if let Some(m) = args.method.as_deref() {
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

    // Клиент через билдер (можно расширять конфиг тут)
    let client = Client::builder().from_uri(&args.uri)?.build();

    let service = service_from_uri(&args.uri).unwrap_or_else(|| "/options".to_string());

    let mut icap_req = Request::new(&icap_method, &service);

    if !args.no204 {
        icap_req = icap_req.allow_204(true);
    }
    if args.allow_206 {
        icap_req = icap_req.allow_206(true);
    }

    for h in &args.xheader {
        match parse_header_line(h) {
            Ok((k, v)) => {
                if k.eq_ignore_ascii_case("preview") {
                    if args.nopreview {
                        warn!("--nopreview set: skipping '{}: {}'", k, v);
                    } else if let Ok(n) = v.parse::<usize>() {
                        icap_req = icap_req.preview(n);
                    } else {
                        warn!("Invalid Preview value in -x: '{}: {}'", k, v);
                    }
                } else {
                    icap_req = icap_req.icap_header(&k, &v);
                }
            }
            Err(e) => warn!("Bad -x header '{}': {}", h, e),
        }
    }

    // CLI превью
    if args.nopreview {
        if args.preview_size.is_some() {
            warn!("--nopreview overrides --preview-size; Preview will not be sent");
        }
    } else if let Some(n) = args.preview_size {
        icap_req = icap_req.preview(n);
    }

    // ── Вложенный HTTP только для REQMOD/RESPMOD
    if icap_method == "REQMOD" || icap_method == "RESPMOD" {
        // Тело из файла (если задано)
        let file_bytes = if let Some(filename) = &args.filename {
            match fs::read(filename) {
                Ok(bytes) => {
                    debug!("Loaded file '{}': {} bytes", filename, bytes.len());
                    Some(bytes)
                }
                Err(e) => {
                    error!("Failed to read file {}: {}", filename, e);
                    return Err(e.into());
                }
            }
        } else {
            None
        };

        if icap_method == "REQMOD" {
            // Сборка HTTP-запроса
            let (host_hdr, uri) = match args.req_url.as_deref() {
                Some(url) => {
                    // Если absolute-form, достанем host; если origin-form — пусть юзер задаст Host через --hx.
                    let host = host_from_url(url).map(|s| s.to_string());
                    (host, url.to_string())
                }
                None => (Some("localhost".into()), "/rs-icap-client".into()),
            };

            let mut builder = HttpRequest::builder()
                .method(Method::GET)
                .version(Version::HTTP_11)
                .uri(uri);

            // Host
            if let Some(h) = host_hdr.as_deref() {
                builder = builder.header("Host", h);
            }

            // Пользовательские request headers (--hx)
            for h in &args.hx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        builder = builder.header(
                            HeaderName::from_bytes(k.as_bytes()).unwrap(),
                            HeaderValue::from_str(&v).unwrap(),
                        );
                    }
                    Err(e) => warn!("Bad --hx header '{}': {}", h, e),
                }
            }

            // Тело
            let body = file_bytes.unwrap_or_default();
            let http_req = builder.body(body).expect("failed to build HTTP request");

            icap_req = icap_req.with_http_request(http_req);
        } else {
            // RESPMOD: собираем HTTP-ответ
            let mut builder = HttpResponse::builder()
                .status(StatusCode::OK)
                .version(Version::HTTP_11);

            // Пользовательские response headers (--rhx)
            for h in &args.rhx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        builder = builder.header(
                            HeaderName::from_bytes(k.as_bytes()).unwrap(),
                            HeaderValue::from_str(&v).unwrap(),
                        );
                    }
                    Err(e) => warn!("Bad --rhx header '{}': {}", h, e),
                }
            }

            if let Some(u) = &args.resp_url {
                builder = builder.header("X-Resp-Source", u);
            }

            let body = file_bytes.unwrap_or_default();
            let http_resp = builder.body(body).expect("failed to build HTTP response");

            icap_req = icap_req.with_http_response(http_resp);
        }
    } else {
        debug!("Sending OPTIONS request");
    }

    info!("Sending {} to {}", icap_method, args.uri);

    // Печать сырого ICAP-запроса (без отправки)
    if args.print_request {
        let bytes = client.get_request(&icap_req)?;
        println!("{}", String::from_utf8_lossy(&bytes));
        return Ok(());
    }

    // Отправка
    match client.send(&icap_req).await {
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
                // тело может быть бинарным — для отладки печатаем как lossy utf8
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

fn parse_header_line(line: &str) -> Result<(String, String), &'static str> {
    if let Some((k, v)) = line.split_once(':') {
        let key = k.trim();
        let val = v.trim();
        if key.is_empty() || val.is_empty() {
            return Err("empty name or value");
        }
        return Ok((key.to_string(), val.to_string()));
    }
    Err("no ':' separator")
}
