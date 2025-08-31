use clap::Parser;
use http::{
    HeaderName, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse, StatusCode,
    Version,
};
use icap_rs::error::IcapResult;
use icap_rs::response::{Response as IcapResponse, StatusCode as IcapStatus};
use icap_rs::{Client, Request};
use std::{fs, path::PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use chrono::Local;
use std::collections::HashSet;
use std::time::Duration;

const BIN_NAME: &str = env!("CARGO_PKG_NAME");
const BIN_VER: &str = env!("CARGO_PKG_VERSION");

pub fn cli_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .header(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .literal(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightCyan))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightCyan))),
        )
        .placeholder(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightBlue))),
        )
}

#[derive(Parser, Debug)]
#[command(
    name = "rs-icap-client",
    about = "Rust ICAP client implementation",
    styles=cli_styles(),
    disable_version_flag = true,
)]
struct Args {
    /// Full ICAP URI like icap://host[:port]/service
    #[arg(short = 'u', long, default_value = "icap://127.0.0.1:1344/")]
    uri: String,

    /// Sends this file to the ICAP server (defaults to RESPMOD like c-icap-client)
    #[arg(short = 'f', long)]
    filename: Option<String>,

    /// Save ICAP response body to file (default: stdout)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Read timeout in seconds (client-side). Default: no timeout (like c-icap-client).
    #[arg(short, long)]
    timeout: Option<u64>,

    /// ICAP method: OPTIONS|REQMOD|RESPMOD
    #[arg(short, long)]
    method: Option<String>,

    /// Send REQMOD with the given request URL (origin-form or absolute URI)
    #[arg(long = "req")]
    req_url: Option<String>,

    /// Send RESPMOD with the given request URL (for tracing)
    #[arg(long = "resp")]
    resp_url: Option<String>,

    /// Debug level to stdout
    #[arg(short = 'd', long)]
    debug_level: Option<u8>,

    /// No-op compatibility flag (kept for parity with c-icap-client)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    noreshdr: bool,

    /// Force c-icap semantics: Preview: 0 (no ieof). Server replies 100, then stream the body.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    nopreview: bool,

    /// Do not allow 204 outside preview
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no204: bool,

    /// Advertise/accept 206
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

    /// Force Preview: N explicitly (advanced). If not set, negotiated via OPTIONS.
    #[arg(short = 'w', long)]
    preview_size: Option<usize>,

    /// Fast 204: with preview-size 0 send ieof immediately
    #[arg(long, action = clap::ArgAction::SetTrue)]
    ieof: bool,

    /// Stream body from file (do not buffer in memory)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    stream_io: bool,

    /// Print ICAP response headers (c-icap-client style)
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the generated ICAP request
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    print_request: bool,
}

#[derive(Debug, Default, Clone)]
struct IcapCaps {
    preview: Option<usize>,
    allow_204_advertised: bool,
    methods: HashSet<String>,
    timeout_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> IcapResult<()> {
    let args = Args::parse();

    // Logging
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

    info!(
        "Starting {BIN_NAME} v{BIN_VER} (using icap-rs v{})",
        icap_rs::LIB_VERSION
    );
    debug!("Arguments: {:?}", args);

    // Pick method: with -f default to RESPMOD like c-icap-client
    let icap_method = if let Some(m) = args.method.as_deref() {
        m.to_uppercase()
    } else if args.req_url.is_some() {
        "REQMOD".to_string()
    } else if args.resp_url.is_some() || args.filename.is_some() {
        "RESPMOD".to_string()
    } else {
        "OPTIONS".to_string()
    };

    // Resolve authority for display
    let (server_host, server_port, _service_for_print) = parse_authority_and_service(&args.uri)
        .unwrap_or_else(|| ("127.0.0.1".into(), 1344, "/".into()));
    let server_ip = tokio::net::lookup_host((server_host.as_str(), server_port))
        .await
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| sa.ip().to_string())
        .unwrap_or_else(|| "?".into());

    let ua = format!(
        "{}/{} (lib: icap-rs/{})",
        BIN_NAME,
        BIN_VER,
        icap_rs::LIB_VERSION
    );

    let client = Client::builder()
        .from_uri(&args.uri)?
        .read_timeout(args.timeout.map(Duration::from_secs))
        .user_agent(&ua)
        .build();
    let service = service_from_uri(&args.uri).unwrap_or_else(|| "/".to_string());

    // Negotiate capabilities unless we're doing a dry-run print
    let mut caps = IcapCaps::default();
    if icap_method != "OPTIONS" && !args.print_request {
        caps = negotiate_caps(&client, &service).await?;
        debug!("Negotiated caps: {:?}", caps);
    }

    let mut icap_req = Request::new(icap_method.as_str(), &service);
    if !args.no204 {
        icap_req = icap_req.allow_204();
    }
    if args.allow_206 {
        icap_req = icap_req.allow_206();
    }

    // Extra ICAP headers (-x)
    for h in &args.xheader {
        match parse_header_line(h) {
            Ok((k, v)) => {
                if k.eq_ignore_ascii_case("preview") {
                    if args.nopreview {
                        warn!(
                            "--nopreview set: skipping explicit Preview override '{}: {}'",
                            k, v
                        );
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

    // Preview semantics
    if args.nopreview {
        icap_req = icap_req.preview(0);
    } else if let Some(n) = args.preview_size {
        icap_req = icap_req.preview(n);
        if args.ieof && n == 0 {
            icap_req = icap_req.preview_ieof();
        }
    } else if icap_method != "OPTIONS"
        && !args.print_request
        && let Some(n) = caps.preview
    {
        icap_req = icap_req.preview(n);
    }

    // Prepare embedded HTTP and body source (in-memory vs streaming)
    let (file_bytes, file_path_opt, file_len_opt) = if let Some(filename) = &args.filename {
        let p = PathBuf::from(filename);
        if args.stream_io || caps.preview == Some(0) || args.nopreview {
            let len = std::fs::metadata(&p).ok().map(|m| m.len());
            debug!("Using stream-io from file '{}' (len={:?})", filename, len);
            (None, Some(p), len)
        } else {
            match fs::read(filename) {
                Ok(bytes) => {
                    let len_u64 = bytes.len() as u64;
                    debug!("Loaded file '{}': {} bytes", filename, len_u64);
                    (Some(bytes), Some(p), Some(len_u64))
                }
                Err(e) => {
                    error!("Failed to read file {}: {}", filename, e);
                    return Err(e.into());
                }
            }
        }
    } else {
        (None, None, None)
    };

    if icap_method == "REQMOD" || icap_method == "RESPMOD" {
        if icap_method == "REQMOD" {
            // Build embedded HTTP request
            let (host_hdr, uri) = match args.req_url.as_deref() {
                Some(url) => {
                    let host = host_from_url(url).map(|s| s.to_string());
                    (host, url.to_string())
                }
                None => (Some("localhost".into()), "/rs-icap-client".into()),
            };

            let body_vec = file_bytes.clone().unwrap_or_default();
            let use_post = !body_vec.is_empty() || file_len_opt.unwrap_or(0) > 0;

            let mut builder = HttpRequest::builder()
                .method(if use_post { Method::POST } else { Method::GET })
                .version(Version::HTTP_10)
                .uri(uri);

            if let Some(h) = host_hdr.as_deref() {
                builder = builder.header("Host", h);
            }
            if args.stream_io
                && let Some(len) = file_len_opt
            {
                builder = builder.header("Content-Length", len.to_string());
            }

            for h in &args.hx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        builder = builder.header(
                            HeaderName::from_bytes(k.as_bytes())?,
                            HeaderValue::from_str(&v)?,
                        );
                    }
                    Err(e) => warn!("Bad --hx header '{}': {}", h, e),
                }
            }

            let http_req = builder
                .body(body_vec)
                .expect("failed to build HTTP request");
            icap_req = icap_req.with_http_request(http_req);
        } else {
            // Build embedded HTTP response (HTTP/1.0 by default, like c-icap-client)
            let mut builder = HttpResponse::builder()
                .status(StatusCode::OK)
                .version(Version::HTTP_10);

            // Simple `Date` and `Last-Modified` similar to c-icap-client output (local time)
            let now_local = Local::now();
            let http_date_simple = now_local.format("%a %b %d %H:%M:%S %Y").to_string();

            builder = builder
                .header("Date", http_date_simple.as_str())
                .header("Last-Modified", http_date_simple.as_str());

            if let Some(len) = file_len_opt {
                builder = builder.header("Content-Length", len.to_string());
            }

            for h in &args.rhx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        builder = builder.header(
                            HeaderName::from_bytes(k.as_bytes())?,
                            HeaderValue::from_str(&v)?,
                        );
                    }
                    Err(e) => warn!("Bad --rhx header '{}': {}", h, e),
                }
            }
            if let Some(u) = &args.resp_url {
                builder = builder.header("X-Resp-Source", u);
            }

            let body_vec = file_bytes.clone().unwrap_or_default();
            let http_resp = builder
                .body(body_vec)
                .expect("failed to build HTTP response");
            icap_req = icap_req.with_http_response(http_resp);
        }

        // Dry-run: print the exact wire bytes and exit
        if args.print_request {
            let forced_preview = if args.nopreview {
                Some(0)
            } else {
                args.preview_size
            };
            let streaming_mode = args.nopreview
                || forced_preview == Some(0)
                || (args.stream_io && forced_preview.unwrap_or(0) == 0);

            let bytes = client.get_request_wire(&icap_req, streaming_mode)?;
            println!("{}", String::from_utf8_lossy(&bytes));
            return Ok(());
        }

        let response = send_with_preview(
            &client,
            icap_req,
            file_path_opt.clone(),
            file_bytes.clone(),
            if args.preview_size.is_none() && !args.nopreview {
                caps.preview
            } else {
                args.preview_size
            },
            args.stream_io,
            args.nopreview,
        )
        .await?;

        output_response(&args, &server_host, &server_ip, server_port, response).await?;
        return Ok(());
    }

    // Explicit OPTIONS
    if icap_method == "OPTIONS" {
        if args.print_request {
            let bytes = client.get_request(&icap_req)?;
            println!("{}", String::from_utf8_lossy(&bytes));
            return Ok(());
        }
        let response = client.send(&icap_req).await?;
        output_response(&args, &server_host, &server_ip, server_port, response).await?;
        return Ok(());
    }

    Ok(())
}

async fn output_response(
    args: &Args,
    server_host: &str,
    server_ip: &str,
    server_port: u16,
    response: IcapResponse,
) -> IcapResult<()> {
    if args.verbose {
        println!(
            "ICAP server:{}, ip:{}, port:{}\n",
            server_host, server_ip, server_port
        );

        if matches!(response.status_code, IcapStatus::NO_CONTENT) {
            println!("No modification needed (Allow 204 response)\n");
        }

        println!("ICAP HEADERS:");
        println!(
            "\t{} {} {}",
            response.version,
            response.status_code.as_str(),
            response.status_text
        );
        for (name, value) in response.headers() {
            let v = value.to_str().unwrap_or("<binary>");
            println!("\t{}: {}", name.as_str(), v);
        }
        println!();

        if let Some(output_file) = &args.output {
            let mut file = File::create(output_file).await?;
            file.write_all(&response.body).await?;
            info!("Response body written to file: {}", output_file);
        } else if !response.body.is_empty() {
            print!("{}", String::from_utf8_lossy(&response.body));
        }
    } else {
        println!("ICAP/1.0 {} {}", response.status_code, response.status_text);

        if let Some(output_file) = &args.output {
            let mut file = File::create(output_file).await?;
            file.write_all(&response.body).await?;
            info!("Response body written to file: {}", output_file);
        } else {
            print!("{}", String::from_utf8_lossy(&response.body));
        }
    }
    Ok(())
}

fn service_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("icap://")?;
    let slash = rest.find('/')?;
    Some(rest[slash..].to_string())
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

fn parse_authority_and_service(uri: &str) -> Option<(String, u16, String)> {
    let s = uri.trim();
    let rest = s.strip_prefix("icap://")?;
    let mut parts = rest.splitn(2, '/');
    let authority = parts.next().unwrap_or(rest);
    let service = format!("/{}", parts.next().unwrap_or(""));

    let (host, port) = if let Some(i) = authority.rfind(':') {
        let h = &authority[..i];
        let p = authority[i + 1..].parse::<u16>().ok()?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), 1344)
    };
    Some((host, port, service))
}

async fn negotiate_caps(client: &Client, service: &str) -> IcapResult<IcapCaps> {
    let opt_req = Request::options(service).allow_204();
    let resp: IcapResponse = client.send(&opt_req).await?;

    let get = |name: &str| -> Option<String> {
        resp.headers()
            .get(name)
            .or_else(|| resp.headers().get(name.to_ascii_lowercase()))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
    };

    let mut caps = IcapCaps::default();

    if let Some(p) = get("Preview")
        && let Ok(n) = p.parse::<usize>()
    {
        caps.preview = Some(n);
    }
    if let Some(allow) = get("Allow") {
        caps.allow_204_advertised = allow
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("204"));
    }
    if let Some(m) = get("Methods") {
        for t in m.split(',').map(|s| s.trim().to_ascii_uppercase()) {
            if !t.is_empty() {
                caps.methods.insert(t);
            }
        }
    }
    if let Some(t) = get("Timeout") {
        caps.timeout_secs = t.parse::<u64>().ok();
    }

    Ok(caps)
}

async fn send_with_preview(
    client: &Client,
    mut icap_req: Request,
    file_path_opt: Option<PathBuf>,
    _file_in_mem: Option<Vec<u8>>,
    negotiated_or_forced_preview: Option<usize>,
    cli_stream_io: bool,
    cli_nopreview: bool,
) -> IcapResult<IcapResponse> {
    // If --nopreview or negotiated Preview:0 → enforce streaming path
    if cli_nopreview || negotiated_or_forced_preview == Some(0) {
        icap_req = icap_req.preview(0);
        return client
            .send_streaming(&icap_req, file_path_opt.expect("file path required"))
            .await;
    }

    // If Preview > 0 → send in-memory (client will handle preview + finalization)
    if let Some(n) = negotiated_or_forced_preview
        && n > 0
    {
        return client.send(&icap_req).await;
    }

    // If preview is unknown but --stream-io requested → behave like Preview:0
    if cli_stream_io && let Some(file_path) = file_path_opt {
        icap_req = icap_req.preview(0);
        return client.send_streaming(&icap_req, file_path).await;
    }

    // Default: in-memory send
    client.send(&icap_req).await
}
