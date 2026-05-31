use clap::Parser;
use clap::builder::styling::{AnsiColor, Color, Style, Styles};

use http::{
    HeaderName, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse, StatusCode,
    Version,
};
use icap_rs::error::IcapResult;
use icap_rs::response::{ParsedResponse as IcapResponse, StatusCode as IcapStatus};
use icap_rs::{Client, Request};
use std::{fs, path::PathBuf};
use tokio::fs::{self as tokio_fs, File};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use chrono::Local;
use std::collections::HashSet;
use std::time::Duration;

const BIN_NAME: &str = env!("CARGO_PKG_NAME");
const BIN_VER: &str = env!("CARGO_PKG_VERSION");

pub const fn cli_styles() -> Styles {
    Styles::styled()
        .usage(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .header(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightCyan))))
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightCyan))),
        )
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlue))))
}

#[derive(Parser, Debug)]
#[command(
    name = "rs-icap-client",
    about = "Rust ICAP client implementation",
    version,
    styles=cli_styles(),
)]
struct Args {
    /// Full ICAP URI, e.g. `icap://host[:port]/service` or `icaps://host[:port]/service`.
    #[arg(short = 'u', long, default_value = "icap://127.0.0.1:1344/")]
    uri: String,

    /// Send this file to the ICAP server (defaults to RESPMOD like c-icap-client).
    #[arg(short = 'f', long)]
    filename: Option<String>,

    /// Save ICAP response body to a file (default: stdout).
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Total timeout in seconds for one ICAP operation. Default: no timeout.
    #[arg(short, long)]
    timeout: Option<u64>,

    /// TCP connect timeout in seconds. Default: no timeout.
    #[arg(long = "connect-timeout")]
    connect_timeout: Option<u64>,

    /// Network write timeout in seconds. Default: no timeout.
    #[arg(long = "write-timeout")]
    write_timeout: Option<u64>,

    /// Timeout in seconds while waiting for `100 Continue` or an early final response.
    #[arg(long = "continue-timeout")]
    continue_timeout: Option<u64>,

    /// ICAP method: `OPTIONS|REQMOD|RESPMOD`.
    #[arg(short, long)]
    method: Option<String>,

    /// Send REQMOD with the given request URL (origin-form or absolute URI).
    #[arg(long = "req")]
    req_url: Option<String>,

    /// Send RESPMOD with the given request URL (for tracing).
    #[arg(long = "resp")]
    resp_url: Option<String>,

    /// Debug level to stdout.
    #[arg(short = 'd', long)]
    debug_level: Option<u8>,

    /// No-op compatibility flag (kept for parity with c-icap-client).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    noreshdr: bool,

    /// Force c-icap semantics: `Preview: 0` (without `ieof`).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    nopreview: bool,

    /// Do not advertise `Allow: 204` outside preview flow.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no204: bool,

    /// Advertise `Allow: 206` and accept partial-content responses.
    #[arg(long = "206", action = clap::ArgAction::SetTrue)]
    allow_206: bool,

    /// Extra ICAP headers (repeatable): `-x "Header: Value"`.
    #[arg(short = 'x', long)]
    xheader: Vec<String>,

    /// Extra HTTP request headers (repeatable): `--hx "Header: Value"`.
    #[arg(long = "hx")]
    hx_header: Vec<String>,

    /// Extra HTTP response headers (repeatable): `--rhx "Header: Value"`.
    #[arg(long = "rhx")]
    rhx_header: Vec<String>,

    /// Disable server certificate verification (rustls).
    /// Equivalent to c-icap-client `-tls-no-verify`. **Insecure.**
    #[arg(long, action = clap::ArgAction::SetTrue)]
    insecure: bool,

    /// Use extra CA bundle (PEM) for TLS (rustls only).
    #[arg(long = "tls-ca", value_name = "PEM_FILE")]
    tls_ca: Option<String>,

    /// Path to a client certificate chain in PEM (rustls only). Pair with
    /// `--tls-key` to enable mutual TLS.
    #[arg(long = "tls-cert", value_name = "PEM_FILE", requires = "tls_key")]
    tls_cert: Option<String>,

    /// Path to the client private key in PEM (rustls only).
    #[arg(long = "tls-key", value_name = "PEM_FILE", requires = "tls_cert")]
    tls_key: Option<String>,

    /// Override SNI hostname (used with TLS; ignored for `icap://`).
    #[arg(long = "sni", value_name = "HOSTNAME")]
    sni: Option<String>,

    /// TLS handshake timeout in seconds (used with TLS; ignored for `icap://`).
    #[arg(long = "tls-handshake-timeout")]
    tls_handshake_timeout: Option<u64>,

    /// Force `Preview: N` explicitly (advanced). If not set, negotiated via OPTIONS.
    #[arg(short = 'w', long)]
    preview_size: Option<usize>,

    /// Fast 204: with preview-size `0`, send `ieof` immediately.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    ieof: bool,

    /// Stream body from file (do not buffer in memory).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    stream_io: bool,

    /// Print ICAP response headers (c-icap-client style).
    #[arg(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print the generated ICAP request.
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

/// Apply CLI TLS arguments (`--tls-ca`, `--tls-cert`/`--tls-key`, `--sni`,
/// `--insecure`) to a `ClientBuilder`. When the crate is built without
/// `tls-rustls`, the TLS flags are reported as noops.
#[cfg(feature = "tls-rustls")]
fn apply_tls_args(
    builder: icap_rs::ClientBuilder,
    args: &Args,
    is_tls_uri: bool,
) -> IcapResult<icap_rs::ClientBuilder> {
    use icap_rs::tls::ClientTlsConfig;

    if !is_tls_uri {
        if args.sni.is_some() {
            eprintln!("Note: --sni is ignored for icap:// (TLS is off).");
        }
        if args.tls_handshake_timeout.is_some() {
            eprintln!("Note: --tls-handshake-timeout is ignored for icap:// (TLS is off).");
        }
        if args.tls_ca.is_some() {
            eprintln!("Note: --tls-ca is ignored for icap:// (TLS is off).");
        }
        if args.tls_cert.is_some() || args.tls_key.is_some() {
            eprintln!("Note: --tls-cert/--tls-key are ignored for icap:// (TLS is off).");
        }
        if args.insecure {
            eprintln!("Note: --insecure is ignored for icap:// (TLS is off).");
        }
        return Ok(builder);
    }

    let mut tls = ClientTlsConfig::with_native_roots();
    if let Some(pem) = &args.tls_ca {
        tls = tls.add_root_ca_pem_file(pem)?;
    }
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        tls = tls.with_client_auth_pem_files(cert, key)?;
    }
    if let Some(sni) = &args.sni {
        tls = tls.with_sni(sni);
    }
    if let Some(secs) = args.tls_handshake_timeout {
        tls = tls.with_handshake_timeout(Duration::from_secs(secs));
    }
    if args.insecure {
        // Mirrors c-icap-client `-tls-no-verify`. Logged at WARN.
        tls = tls.dangerous_disable_cert_verification()?;
    }
    Ok(builder.with_tls(tls))
}

// Mirror the `tls-rustls` signature so the call site needs no cfg.
#[cfg(not(feature = "tls-rustls"))]
#[allow(clippy::unnecessary_wraps)]
fn apply_tls_args(
    builder: icap_rs::ClientBuilder,
    args: &Args,
    is_tls_uri: bool,
) -> IcapResult<icap_rs::ClientBuilder> {
    if is_tls_uri {
        eprintln!(
            "Error: `icaps://` requested but this binary was built without feature `tls-rustls`."
        );
        std::process::exit(2);
    }
    for (flag, set) in [
        ("--tls-ca", args.tls_ca.is_some()),
        ("--tls-cert", args.tls_cert.is_some()),
        ("--tls-key", args.tls_key.is_some()),
        ("--sni", args.sni.is_some()),
        (
            "--tls-handshake-timeout",
            args.tls_handshake_timeout.is_some(),
        ),
        ("--insecure", args.insecure),
    ] {
        if set {
            eprintln!("Note: {flag} requires a binary built with feature `tls-rustls`.");
        }
    }
    Ok(builder)
}

#[tokio::main]
async fn main() -> IcapResult<()> {
    let args = Args::parse();

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

    let icap_method = if let Some(m) = args.method.as_deref() {
        m.to_uppercase()
    } else if args.req_url.is_some() {
        "REQMOD".to_string()
    } else if args.resp_url.is_some() || args.filename.is_some() {
        "RESPMOD".to_string()
    } else {
        "OPTIONS".to_string()
    };

    let (server_host, server_port, _service_for_print) = parse_authority_and_service(&args.uri)
        .unwrap_or_else(|| ("127.0.0.1".into(), 1344, "/".into()));
    let server_ip = tokio::net::lookup_host((server_host.as_str(), server_port))
        .await
        .ok()
        .and_then(|mut it| it.next())
        .map_or_else(|| "?".into(), |sa| sa.ip().to_string());

    let ua = format!(
        "{}/{} (lib: icap-rs/{})",
        BIN_NAME,
        BIN_VER,
        icap_rs::LIB_VERSION
    );

    let builder = Client::builder().with_uri(&args.uri)?;
    let is_tls_uri = args.uri.starts_with("icaps://");
    let builder = apply_tls_args(builder, &args, is_tls_uri)?;

    let client = builder
        .timeout(args.timeout.map(Duration::from_secs))
        .connect_timeout(args.connect_timeout.map(Duration::from_secs))
        .write_timeout(args.write_timeout.map(Duration::from_secs))
        .continue_timeout(args.continue_timeout.map(Duration::from_secs))
        .user_agent(&ua)
        .build();
    let service = service_from_uri(&args.uri).unwrap_or_else(|| "/".to_string());

    // Negotiate capabilities unless we're doing a dry-run print
    let mut caps = IcapCaps::default();
    if icap_method != "OPTIONS" && !args.print_request {
        caps = negotiate_caps(&client, &service).await?;
        debug!("Negotiated caps: {:?}", caps);
    }

    let mut icap_req = Request::try_new(icap_method.as_str(), &service)?;
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
    let effective_preview = icap_req.preview_size();

    // Prepare embedded HTTP and body source
    let (file_bytes, file_path_opt, file_len_opt) = if let Some(filename) = &args.filename {
        let p = PathBuf::from(filename);
        if should_stream_file_body(args.stream_io, effective_preview) {
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
    let stream_file_body = file_path_opt.is_some() && file_bytes.is_none();
    if stream_file_body && effective_preview.is_none() {
        icap_req = icap_req.preview(0);
    }
    let effective_preview = icap_req.preview_size();
    validate_ieof_body(
        args.ieof,
        file_path_opt.is_some(),
        file_len_opt,
        effective_preview,
    )?;

    if icap_method == "REQMOD" || icap_method == "RESPMOD" {
        if icap_method == "REQMOD" {
            // Build embedded HTTP request
            let (host_hdr, uri) = args.req_url.as_deref().map_or_else(
                || (Some("localhost".into()), "/rs-icap-client".into()),
                |url| {
                    (
                        host_from_url(url).map(std::string::ToString::to_string),
                        url.to_string(),
                    )
                },
            );

            let body_vec = file_bytes.clone().unwrap_or_default();
            let use_post = !body_vec.is_empty() || file_len_opt.unwrap_or(0) > 0;

            let mut httpb = HttpRequest::builder()
                .method(if use_post { Method::POST } else { Method::GET })
                .version(Version::HTTP_10)
                .uri(uri);

            if let Some(h) = host_hdr.as_deref() {
                httpb = httpb.header("Host", h);
            }
            if let Some(len) = file_len_opt {
                httpb = httpb.header("Content-Length", len.to_string());
            }

            for h in &args.hx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        httpb = httpb.header(
                            HeaderName::from_bytes(k.as_bytes())?,
                            HeaderValue::from_str(&v)?,
                        );
                    }
                    Err(e) => warn!("Bad --hx header '{}': {}", h, e),
                }
            }

            if stream_file_body {
                let http_req = httpb.body(()).map_err(|e| {
                    icap_rs::Error::http_parse(format!("failed to build HTTP request head: {e}"))
                })?;
                icap_req = icap_req.with_http_request_head(http_req)?;
            } else {
                let http_req = httpb.body(body_vec).map_err(|e| {
                    icap_rs::Error::http_parse(format!("failed to build HTTP request: {e}"))
                })?;
                icap_req = icap_req.with_http_request(http_req)?;
            }
        } else {
            // Build embedded HTTP response (HTTP/1.0 by default, like c-icap-client)
            let mut httpb = HttpResponse::builder()
                .status(StatusCode::OK)
                .version(Version::HTTP_10);

            // RFC 2822 date with local timezone offset (required by RFC 3507 §4.10.2)
            let http_date_rfc2822 = Local::now().to_rfc2822();

            httpb = httpb
                .header("Date", http_date_rfc2822.as_str())
                .header("Last-Modified", http_date_rfc2822.as_str());

            if let Some(len) = file_len_opt {
                httpb = httpb.header("Content-Length", len.to_string());
            }

            for h in &args.rhx_header {
                match parse_header_line(h) {
                    Ok((k, v)) => {
                        httpb = httpb.header(
                            HeaderName::from_bytes(k.as_bytes())?,
                            HeaderValue::from_str(&v)?,
                        );
                    }
                    Err(e) => warn!("Bad --rhx header '{}': {}", h, e),
                }
            }
            if let Some(u) = &args.resp_url {
                httpb = httpb.header("X-Resp-Source", u);
            }

            let body_vec = file_bytes.clone().unwrap_or_default();
            if stream_file_body {
                let http_resp = httpb.body(()).map_err(|e| {
                    icap_rs::Error::http_parse(format!("failed to build HTTP response head: {e}"))
                })?;
                icap_req = icap_req.with_http_response_head(http_resp)?;
            } else {
                let http_resp = httpb.body(body_vec).map_err(|e| {
                    icap_rs::Error::http_parse(format!("failed to build HTTP response: {e}"))
                })?;
                icap_req = icap_req.with_http_response(http_resp)?;
            }
        }

        // Dry-run: print the exact wire bytes and exit
        if args.print_request {
            let streaming_mode = stream_file_body;
            let bytes = client.get_request_wire(&icap_req, streaming_mode)?;
            println!("{}", String::from_utf8_lossy(&bytes));
            return Ok(());
        }

        let response = send_with_preview(
            &client,
            icap_req,
            file_path_opt.clone(),
            effective_preview,
            stream_file_body,
            args.nopreview,
        )
        .await?;

        output_response(
            &args,
            &server_host,
            &server_ip,
            server_port,
            response,
            file_path_opt.as_ref(),
            file_bytes.as_deref(),
        )
        .await?;
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
        output_response(
            &args,
            &server_host,
            &server_ip,
            server_port,
            response,
            None,
            None,
        )
        .await?;
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
    original_body_path: Option<&PathBuf>,
    original_body_bytes: Option<&[u8]>,
) -> IcapResult<()> {
    let output_body =
        response_output_body(&response, original_body_path, original_body_bytes).await?;

    if args.verbose {
        println!("ICAP server:{server_host}, ip:{server_ip}, port:{server_port}\n");

        if matches!(response.status_code(), IcapStatus::NO_CONTENT) {
            println!("No modification needed (Allow 204 response)\n");
        } else if let Some(offset) = response.use_original_body_offset() {
            println!("Partial content uses original body from offset {offset}\n");
        }

        println!("ICAP HEADERS:");
        println!(
            "\t{} {} {}",
            response.version(),
            response.status_code().as_str(),
            response.status_text()
        );
        for (name, value) in response.headers() {
            let v = value.to_str().unwrap_or("<binary>");
            println!("\t{}: {}", name.as_str(), v);
        }
        println!();

        if let Some(output_file) = &args.output {
            let mut file = File::create(output_file).await?;
            file.write_all(&output_body).await?;
            info!("Response body written to file: {}", output_file);
        } else if !output_body.is_empty() {
            print!("{}", String::from_utf8_lossy(&output_body));
        }
    } else {
        println!(
            "ICAP/1.0 {} {}",
            response.status_code(),
            response.status_text()
        );
        if let Some(output_file) = &args.output {
            let mut file = File::create(output_file).await?;
            file.write_all(&output_body).await?;
            info!("Response body written to file: {}", output_file);
        } else {
            print!("{}", String::from_utf8_lossy(&output_body));
        }
    }
    Ok(())
}

async fn response_output_body(
    response: &IcapResponse,
    original_body_path: Option<&PathBuf>,
    original_body_bytes: Option<&[u8]>,
) -> IcapResult<Vec<u8>> {
    let Some(offset) = response.use_original_body_offset() else {
        return Ok(response.body().to_vec());
    };

    let original_body = if let Some(bytes) = original_body_bytes {
        bytes.to_vec()
    } else if let Some(path) = original_body_path {
        tokio_fs::read(path).await?
    } else {
        Vec::new()
    };

    append_original_body_suffix(response.body().to_vec(), &original_body, offset)
}

fn append_original_body_suffix(
    mut response_body: Vec<u8>,
    original_body: &[u8],
    offset: usize,
) -> IcapResult<Vec<u8>> {
    if offset > original_body.len() {
        return Err(icap_rs::Error::body(format!(
            "use-original-body offset {offset} exceeds original body length {}",
            original_body.len()
        )));
    }

    response_body.extend_from_slice(&original_body[offset..]);
    Ok(response_body)
}

fn service_from_uri(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("icap://")
        .or_else(|| uri.strip_prefix("icaps://"))?;
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
    let (tls, rest) = if let Some(r) = uri.strip_prefix("icaps://") {
        (true, r)
    } else if let Some(r) = uri.strip_prefix("icap://") {
        (false, r)
    } else {
        return None;
    };

    let mut parts = rest.splitn(2, '/');
    let authority = parts.next().unwrap_or(rest);
    let service = format!("/{}", parts.next().unwrap_or(""));

    let (host, port) = if let Some(i) = authority.rfind(':') {
        let h = &authority[..i];
        let p = authority[i + 1..].parse::<u16>().ok()?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), if tls { 11344 } else { 1344 })
    };
    Some((host, port, service))
}

const fn should_stream_file_body(cli_stream_io: bool, preview_size: Option<usize>) -> bool {
    cli_stream_io || matches!(preview_size, Some(0))
}

fn validate_ieof_body(
    ieof: bool,
    has_file: bool,
    file_len: Option<u64>,
    preview_size: Option<usize>,
) -> IcapResult<()> {
    if !ieof || !has_file || preview_size != Some(0) {
        return Ok(());
    }

    match file_len {
        Some(0) => Ok(()),
        Some(len) => Err(icap_rs::Error::body(format!(
            "--ieof with Preview: 0 is only valid when the complete body is already in the preview; file has {len} byte(s)"
        ))),
        None => Err(icap_rs::Error::body(
            "--ieof with Preview: 0 requires proving that the file body is empty",
        )),
    }
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
    negotiated_or_forced_preview: Option<usize>,
    stream_file_body: bool,
    cli_nopreview: bool,
) -> IcapResult<IcapResponse> {
    if stream_file_body && let Some(file_path) = file_path_opt {
        if cli_nopreview || negotiated_or_forced_preview == Some(0) {
            icap_req = icap_req.preview(0);
        } else if let Some(n) = negotiated_or_forced_preview {
            icap_req = icap_req.preview(n);
        } else {
            // c-icap-client compatibility: streaming uploads use a Preview: 0
            // gate unless the server or caller selected a larger preview.
            icap_req = icap_req.preview(0);
        }
        return client.send_streaming(&icap_req, file_path).await;
    }

    if cli_nopreview || negotiated_or_forced_preview == Some(0) {
        icap_req = icap_req.preview(0);
        return client.send(&icap_req).await;
    }

    if let Some(n) = negotiated_or_forced_preview
        && n > 0
    {
        return client.send(&icap_req).await;
    }

    client.send(&icap_req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_body_mode_covers_preview_variants() {
        assert!(should_stream_file_body(true, Some(4)));
        assert!(should_stream_file_body(true, None));
        assert!(should_stream_file_body(false, Some(0)));
        assert!(!should_stream_file_body(false, Some(4)));
        assert!(!should_stream_file_body(false, None));
    }

    #[test]
    fn rejects_ieof_for_non_empty_file_body() {
        let err = validate_ieof_body(true, true, Some(5), Some(0))
            .expect_err("non-empty file cannot be sent as Preview: 0 ieof");

        assert!(err.to_string().contains("--ieof"));
    }

    #[test]
    fn accepts_ieof_for_empty_file_body() {
        validate_ieof_body(true, true, Some(0), Some(0)).expect("empty body can use ieof");
    }

    #[test]
    fn appends_original_body_suffix_from_offset() {
        let body =
            append_original_body_suffix(b"HTTP/1.1 200 OK\r\n\r\nabc".to_vec(), b"abcdef", 3)
                .expect("append original suffix");

        assert_eq!(body, b"HTTP/1.1 200 OK\r\n\r\nabcdef");
    }

    #[test]
    fn rejects_original_body_offset_past_input() {
        let err = append_original_body_suffix(Vec::new(), b"abc", 4)
            .expect_err("offset past original body must fail");

        assert!(err.to_string().contains("exceeds original body length"));
    }

    async fn read_until_contains(stream: &mut tokio::net::TcpStream, needle: &[u8]) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            if buf.windows(needle.len()).any(|window| window == needle) {
                return buf;
            }
            let n = stream.read(&mut tmp).await.expect("read from client");
            assert!(n > 0, "connection closed before expected bytes arrived");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    #[tokio::test]
    async fn stream_io_preview_n_sends_preview_and_remainder() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rs-icap-client-stream-{}-{unique}.txt",
            std::process::id()
        ));
        std::fs::write(&path, b"hello").expect("write temp body");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let preview = read_until_contains(&mut socket, b"4\r\nhell\r\n0\r\n\r\n").await;
            let preview_text = String::from_utf8_lossy(&preview);
            assert!(preview_text.contains("\r\nPreview: 4\r\n"));
            assert!(preview_text.contains("Encapsulated: req-hdr=0, req-body="));

            socket
                .write_all(b"ICAP/1.0 100 Continue\r\n\r\n")
                .await
                .expect("write continue");

            let remainder = read_until_contains(&mut socket, b"1\r\no\r\n0\r\n\r\n").await;
            assert!(
                String::from_utf8_lossy(&remainder).contains("1\r\no\r\n0\r\n\r\n"),
                "missing streamed remainder"
            );

            socket
                .write_all(
                    b"ICAP/1.0 204 No Content\r\n\
                      ISTag: \"stream-test\"\r\n\
                      Encapsulated: null-body=0\r\n\r\n",
                )
                .await
                .expect("write response");
        });

        let client = Client::builder().host("127.0.0.1").port(port).build();
        let http = HttpRequest::builder()
            .method(Method::POST)
            .uri("/")
            .version(Version::HTTP_10)
            .header("Host", "origin.example")
            .header("Content-Length", "5")
            .body(())
            .expect("build HTTP head");
        let req = Request::reqmod("scan")
            .preview(4)
            .with_http_request_head(http)
            .expect("build ICAP request");

        let response = send_with_preview(&client, req, Some(path.clone()), Some(4), true, false)
            .await
            .expect("send streaming preview");

        assert_eq!(response.status_code(), IcapStatus::NO_CONTENT);
        server.await.expect("server task");
        let _ = std::fs::remove_file(path);
    }
}
