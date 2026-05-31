use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Request as HttpRequest, Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::HandlerResult;
use icap_rs::error::IcapResult;
use icap_rs::request::{Body, EmbeddedHttp, IncomingRequest, Request};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::{Client, Method, OptionsCacheConfig, PreviewDecision, ServiceOptions};
use std::hint::black_box;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::{Builder as RtBuilder, Runtime};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

// Concurrency levels for the parallel server benchmark.
// Starts at 4: the single-connection case is already covered by `server_rps`.
const CONCURRENCY_LEVELS: &[usize] = &[4, 16];
/// Body size used in OPTIONS cache benchmarks.
///
/// 512 bytes is representative of a typical small HTTP POST payload (JSON API
/// request, short form submission). Large enough to include realistic
/// serialization work, small enough that the OPTIONS round-trip overhead
/// remains clearly visible in `cache_cold_per_iter`.
const CACHE_BENCH_BODY_SIZE: usize = 512;
const STREAMING_BODY_SIZE: usize = 64 * 1024;
const STREAMING_PREVIEW_SIZE: usize = STREAMING_PREVIEW_SIZE_U32 as usize;
const STREAMING_PREVIEW_SIZE_U32: u32 = 1024;
const RESPONSE_BODY_SIZE: usize = 64 * 1024;
const SERVER_PREVIEW_SIZE: usize = SERVER_PREVIEW_SIZE_U32 as usize;
const SERVER_PREVIEW_SIZE_U32: u32 = 4;
const SERVER_PREVIEW_BODY: &[u8] = b"abcdefghij";

struct BenchEnv {
    rt: Runtime,
    client: Client,
    request_204: Request,
    request_200: Request,
    stream_no_preview: Request,
    stream_preview_0: Request,
    stream_preview_n: Request,
    stream_body: Vec<u8>,
    wire_request_204: Vec<u8>,
    wire_request_200: Vec<u8>,
    wire_preview_early: Vec<u8>,
    wire_preview_continue: Vec<u8>,
    wire_preview_remainder: Vec<u8>,
    addr: String,
}

impl BenchEnv {
    fn new() -> Self {
        let port = reserve_port();
        let addr = format!("127.0.0.1:{port}");

        let rt = RtBuilder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("build tokio runtime for bench");

        rt.block_on(async {
            let server = Server::builder()
                .bind(&addr)
                .route(
                    "respmod",
                    [Method::RespMod],
                    fast_204_handler,
                    Some(ServiceOptions::new().with_static_istag("bench-204")),
                )
                .route(
                    "respmod-200",
                    [Method::RespMod],
                    body_200_handler,
                    Some(ServiceOptions::new().with_static_istag("bench-200")),
                )
                .route_reqmod(
                    "preview-early",
                    preview_early_handler,
                    Some(
                        ServiceOptions::new()
                            .with_static_istag("bench-preview")
                            .with_preview(SERVER_PREVIEW_SIZE_U32)
                            .add_allow("204"),
                    ),
                )
                .route_reqmod(
                    "preview-continue",
                    preview_continue_handler,
                    Some(
                        ServiceOptions::new()
                            .with_static_istag("bench-preview")
                            .with_preview(SERVER_PREVIEW_SIZE_U32)
                            .add_allow("204"),
                    ),
                )
                .build()
                .await
                .expect("build benchmark server");

            tokio::spawn(async move {
                let _ = server.run().await;
            });
            wait_port_ready(&addr)
                .await
                .expect("benchmark server ready");
        });

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .keep_alive(true)
            .build();

        let request_204 = Request::respmod("respmod")
            .allow_204()
            .with_http_response(sample_http_response())
            .expect("build benchmark request");

        let request_200 = Request::respmod("respmod-200")
            .allow_204()
            .with_http_response(sample_http_response())
            .expect("build benchmark body request");

        let stream_no_preview = streaming_respmod_request("respmod", None);
        let stream_preview_0 = streaming_respmod_request("respmod", Some(0));
        let stream_preview_n = streaming_respmod_request("respmod", Some(STREAMING_PREVIEW_SIZE));
        let stream_body = vec![42u8; STREAMING_BODY_SIZE];

        let wire_request_204 = client
            .get_request(&request_204)
            .expect("build 204 wire request for raw bench");
        let wire_request_200 = client
            .get_request(&request_200)
            .expect("build 200 wire request for raw bench");

        let wire_preview_early = preview_initial_wire(&addr, "preview-early");
        let wire_preview_continue = preview_initial_wire(&addr, "preview-continue");
        let wire_preview_remainder = preview_remainder_wire();

        Self {
            rt,
            client,
            request_204,
            request_200,
            stream_no_preview,
            stream_preview_0,
            stream_preview_n,
            stream_body,
            wire_request_204,
            wire_request_200,
            wire_preview_early,
            wire_preview_continue,
            wire_preview_remainder,
            addr,
        }
    }
}

async fn fast_204_handler(_req: IncomingRequest) -> HandlerResult<Response> {
    Ok(Response::new(StatusCode::NO_CONTENT, "No Content")
        .try_set_istag("bench-204")?
        .add_header("Server", "icap-rs/bench"))
}

async fn body_200_handler(_req: IncomingRequest) -> HandlerResult<Response> {
    let http = sample_http_response_with_body(RESPONSE_BODY_SIZE);
    Ok(Response::ok_with_istag("bench-200")?.with_http_response(&http)?)
}

async fn preview_early_handler(req: IncomingRequest) -> HandlerResult<PreviewDecision> {
    let Some(EmbeddedHttp::Req { body, .. }) = req.into_embedded() else {
        return Ok(PreviewDecision::Respond(Response::no_content_with_istag(
            "bench-preview",
        )?));
    };

    match body {
        Body::Preview { bytes, .. } => {
            black_box(bytes.len());
            Ok(PreviewDecision::Respond(Response::no_content_with_istag(
                "bench-preview",
            )?))
        }
        Body::Full { reader } => {
            black_box(reader.len());
            Ok(PreviewDecision::Respond(Response::no_content_with_istag(
                "bench-preview",
            )?))
        }
        Body::Empty => Ok(PreviewDecision::Respond(Response::no_content_with_istag(
            "bench-preview",
        )?)),
    }
}

async fn preview_continue_handler(req: IncomingRequest) -> HandlerResult<PreviewDecision> {
    let Some(EmbeddedHttp::Req { body, .. }) = req.into_embedded() else {
        return Ok(PreviewDecision::Respond(Response::no_content_with_istag(
            "bench-preview",
        )?));
    };

    match body {
        Body::Preview { bytes, .. } => {
            black_box(bytes.len());
            Ok(PreviewDecision::Continue)
        }
        Body::Full { reader } => {
            black_box(reader.len());
            Ok(PreviewDecision::Respond(Response::no_content_with_istag(
                "bench-preview",
            )?))
        }
        Body::Empty => Ok(PreviewDecision::Respond(Response::no_content_with_istag(
            "bench-preview",
        )?)),
    }
}

fn sample_http_response() -> HttpResponse<Vec<u8>> {
    sample_http_response_with_body(5)
}

fn sample_http_request() -> HttpRequest<Vec<u8>> {
    let body = vec![42u8; CACHE_BENCH_BODY_SIZE];
    HttpRequest::builder()
        .method("POST")
        .uri("http://example.local/upload")
        .version(Version::HTTP_11)
        .header("Host", "example.local")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", body.len().to_string())
        .body(body)
        .expect("build sample http request")
}

fn sample_http_response_with_body(body_size: usize) -> HttpResponse<Vec<u8>> {
    let body = vec![42u8; body_size];
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", body.len().to_string())
        .body(body)
        .expect("build sample http response")
}

fn sample_http_response_head(body_size: usize) -> HttpResponse<()> {
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", body_size.to_string())
        .body(())
        .expect("build sample http response head")
}

fn streaming_respmod_request(service: &str, preview_size: Option<usize>) -> Request {
    let mut req = Request::respmod(service).allow_204();
    if let Some(n) = preview_size {
        req = req.preview(n);
    }
    req.with_http_response_head(sample_http_response_head(STREAMING_BODY_SIZE))
        .expect("build streaming response request")
}

fn preview_initial_wire(addr: &str, service: &str) -> Vec<u8> {
    let http_head = format!(
        "POST /upload HTTP/1.1\r\nHost: example.local\r\nContent-Length: {}\r\n\r\n",
        SERVER_PREVIEW_BODY.len()
    );
    let req_body_off = http_head.len();
    let mut wire = format!(
        "REQMOD icap://{addr}/{service} ICAP/1.0\r\n\
         Host: {addr}\r\n\
         Allow: 204\r\n\
         Preview: {SERVER_PREVIEW_SIZE}\r\n\
         Encapsulated: req-hdr=0, req-body={req_body_off}\r\n\
         \r\n\
         {http_head}",
    )
    .into_bytes();
    wire.extend_from_slice(format!("{SERVER_PREVIEW_SIZE:X}\r\n").as_bytes());
    wire.extend_from_slice(&SERVER_PREVIEW_BODY[..SERVER_PREVIEW_SIZE]);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    wire
}

fn preview_remainder_wire() -> Vec<u8> {
    let remainder = &SERVER_PREVIEW_BODY[SERVER_PREVIEW_SIZE..];
    let mut wire = format!("{:X}\r\n", remainder.len()).into_bytes();
    wire.extend_from_slice(remainder);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    wire
}

fn reserve_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

async fn wait_port_ready(addr: &str) -> IcapResult<()> {
    let socket = connect_with_retry(addr).await?;
    drop(socket);
    Ok(())
}

fn headers_complete(buf: &[u8]) -> bool {
    find_double_crlf(buf).is_some()
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn encapsulated_body_offset(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("Encapsulated") {
            continue;
        }
        for part in value.split(',').map(str::trim) {
            let Some((key, offset)) = part.split_once('=') else {
                continue;
            };
            if matches!(key.trim(), "req-body" | "res-body" | "opt-body")
                && let Ok(offset) = offset.trim().parse::<usize>()
            {
                return Some(offset);
            }
        }
    }
    None
}

fn chunked_entity_complete(buf: &[u8], mut pos: usize) -> bool {
    loop {
        let Some(line_len) = find_crlf(&buf[pos..]) else {
            return false;
        };
        let line_end = pos + line_len;
        let size_line = &buf[pos..line_end];
        let size_token = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
        let Ok(size_text) = std::str::from_utf8(size_token) else {
            return false;
        };
        let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
            return false;
        };
        let after_line = line_end + 2;

        if size == 0 {
            let trailers = &buf[after_line..];
            return trailers.starts_with(b"\r\n") || find_double_crlf(trailers).is_some();
        }

        let after_data = after_line.saturating_add(size);
        if buf.len() < after_data + 2 {
            return false;
        }
        pos = after_data + 2;
    }
}

fn icap_response_message_complete(buf: &[u8]) -> bool {
    let Some(header_end) = find_double_crlf(buf) else {
        return false;
    };
    let body_offset = encapsulated_body_offset(&buf[..header_end]).unwrap_or(usize::MAX);
    if body_offset == usize::MAX {
        return true;
    }
    let body_start = header_end + 4 + body_offset;
    if buf.len() < body_start {
        return false;
    }
    chunked_entity_complete(buf, body_start)
}

async fn read_icap_headers(socket: &mut TcpStream) -> IcapResult<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut tmp = [0u8; 1024];
    loop {
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
        if headers_complete(&out) {
            break;
        }
    }
    Ok(out)
}

async fn read_icap_chunked_message(socket: &mut TcpStream) -> IcapResult<Vec<u8>> {
    let mut out = Vec::with_capacity(RESPONSE_BODY_SIZE + 512);
    let mut tmp = [0u8; 8192];
    loop {
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
        if icap_response_message_complete(&out) {
            break;
        }
    }
    Ok(out)
}

async fn connect_with_retry(addr: &str) -> IcapResult<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                last_err = Some(e);
                sleep(Duration::from_millis(2)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::other("connect retry exhausted"))
        .into())
}

async fn build_socket_pool(
    addr: &str,
    concurrency: usize,
) -> IcapResult<Arc<Vec<Arc<Mutex<TcpStream>>>>> {
    let mut sockets = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let socket = connect_with_retry(addr).await?;
        sockets.push(Arc::new(Mutex::new(socket)));
    }
    Ok(Arc::new(sockets))
}

async fn run_raw_parallel_keepalive_once(
    sockets: Arc<Vec<Arc<Mutex<TcpStream>>>>,
    wire: Arc<Vec<u8>>,
) -> IcapResult<()> {
    let mut set = JoinSet::new();
    for socket in sockets.iter() {
        let socket = Arc::clone(socket);
        let wire = Arc::clone(&wire);
        set.spawn(async move {
            let mut socket = socket.lock().await;
            socket.write_all(&wire).await?;
            socket.flush().await?;
            let response = read_icap_headers(&mut socket).await;
            drop(socket);
            response
        });
    }
    while let Some(joined) = set.join_next().await {
        let resp = joined
            .map_err(|e| icap_rs::Error::unexpected(format!("raw task join error: {e}")))??;
        black_box(resp);
    }
    Ok(())
}

async fn run_preview_early_once(socket: &mut TcpStream, wire: &[u8]) -> IcapResult<()> {
    socket.write_all(wire).await?;
    socket.flush().await?;
    let response = read_icap_headers(socket).await?;
    black_box(response);
    Ok(())
}

async fn run_preview_continue_once(
    socket: &mut TcpStream,
    initial: &[u8],
    remainder: &[u8],
) -> IcapResult<()> {
    socket.write_all(initial).await?;
    socket.flush().await?;
    let interim = read_icap_headers(socket).await?;
    black_box(interim);

    socket.write_all(remainder).await?;
    socket.flush().await?;
    let final_response = read_icap_headers(socket).await?;
    black_box(final_response);
    Ok(())
}

fn bench_client_rps(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("client_rps");
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("send_respmod_204_keepalive", 1),
        &1usize,
        |b, _| {
            b.iter(|| {
                env.rt.block_on(async {
                    let resp = env
                        .client
                        .send(&env.request_204)
                        .await
                        .expect("client send");
                    black_box(resp.status_code());
                });
            });
        },
    );
    group.finish();
}

fn bench_client_body_rps(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("client_body_rps");
    group.throughput(Throughput::Bytes(RESPONSE_BODY_SIZE as u64));
    group.bench_with_input(
        BenchmarkId::new("send_respmod_200_body_keepalive", RESPONSE_BODY_SIZE),
        &RESPONSE_BODY_SIZE,
        |b, _| {
            b.iter(|| {
                env.rt.block_on(async {
                    let resp = env
                        .client
                        .send(&env.request_200)
                        .await
                        .expect("client body send");
                    black_box(resp.body().len());
                });
            });
        },
    );
    group.finish();
}

fn bench_client_streaming_rps(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("client_streaming_rps");
    group.throughput(Throughput::Bytes(STREAMING_BODY_SIZE as u64));

    for (name, req) in [
        ("send_streaming_respmod_no_preview", &env.stream_no_preview),
        ("send_streaming_respmod_preview_0", &env.stream_preview_0),
        (
            "send_streaming_respmod_preview_n_continue",
            &env.stream_preview_n,
        ),
    ] {
        group.bench_with_input(
            BenchmarkId::new(name, STREAMING_BODY_SIZE),
            req,
            |b, req| {
                b.iter(|| {
                    env.rt.block_on(async {
                        let resp = env
                            .client
                            .send_streaming_reader(req, env.stream_body.as_slice())
                            .await
                            .expect("streaming client send");
                        black_box(resp.status_code());
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_server_rps(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("server_rps");
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("raw_tcp_respmod_204_keepalive", 1),
        &1usize,
        |b, _| {
            let mut socket = env
                .rt
                .block_on(connect_with_retry(&env.addr))
                .expect("connect keepalive socket");
            b.iter(|| {
                let resp = env.rt.block_on(async {
                    socket.write_all(&env.wire_request_204).await?;
                    socket.flush().await?;
                    read_icap_headers(&mut socket).await
                });
                let resp = resp.expect("raw keepalive send");
                black_box(resp);
            });
        },
    );
    group.finish();
}

fn bench_server_body_rps(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("server_body_rps");
    group.throughput(Throughput::Bytes(RESPONSE_BODY_SIZE as u64));
    group.bench_with_input(
        BenchmarkId::new("raw_tcp_respmod_200_body_keepalive", RESPONSE_BODY_SIZE),
        &RESPONSE_BODY_SIZE,
        |b, _| {
            let mut socket = env
                .rt
                .block_on(connect_with_retry(&env.addr))
                .expect("connect body keepalive socket");
            b.iter(|| {
                let resp = env.rt.block_on(async {
                    socket.write_all(&env.wire_request_200).await?;
                    socket.flush().await?;
                    read_icap_chunked_message(&mut socket).await
                });
                let resp = resp.expect("raw body keepalive send");
                black_box(resp);
            });
        },
    );
    group.finish();
}

fn bench_server_rps_parallel(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("server_rps_parallel");
    for &concurrency in CONCURRENCY_LEVELS {
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("raw_tcp_respmod_204_keepalive", concurrency),
            &concurrency,
            |b, &cc| {
                let sockets = env
                    .rt
                    .block_on(build_socket_pool(&env.addr, cc))
                    .expect("build keepalive socket pool");
                let wire = Arc::new(env.wire_request_204.clone());
                b.iter(|| {
                    env.rt
                        .block_on(run_raw_parallel_keepalive_once(
                            Arc::clone(&sockets),
                            Arc::clone(&wire),
                        ))
                        .expect("parallel raw burst");
                });
            },
        );
    }
    group.finish();
}

fn bench_server_preview_route(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("server_preview_route");
    group.throughput(Throughput::Elements(1));

    group.bench_function("raw_tcp_reqmod_preview_early_final", |b| {
        let mut socket = env
            .rt
            .block_on(connect_with_retry(&env.addr))
            .expect("connect preview early socket");
        b.iter(|| {
            env.rt
                .block_on(run_preview_early_once(&mut socket, &env.wire_preview_early))
                .expect("preview early request");
        });
    });

    group.bench_function("raw_tcp_reqmod_preview_continue", |b| {
        let mut socket = env
            .rt
            .block_on(connect_with_retry(&env.addr))
            .expect("connect preview continue socket");
        b.iter(|| {
            env.rt
                .block_on(run_preview_continue_once(
                    &mut socket,
                    &env.wire_preview_continue,
                    &env.wire_preview_remainder,
                ))
                .expect("preview continue request");
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// OPTIONS cache benchmarks
// ---------------------------------------------------------------------------

/// Null-body REQMOD handler that returns the *same* `ISTag` advertised in
/// `ServiceOptions`. A matching `ISTag` prevents `reconcile_istag` from
/// invalidating the cache on every response, which would make the "warm cache"
/// variant behave identically to "cold cache" and defeat the measurement.
async fn reqmod_204_cache_handler(_req: IncomingRequest) -> HandlerResult<Response> {
    Ok(Response::no_content().try_set_istag("bench-cache")?)
}

/// Benchmark environment for the OPTIONS cache comparison.
///
/// Starts one REQMOD server that also serves OPTIONS (via `ServiceOptions`
/// with `Options-TTL: 3600` and `ISTag: "bench-cache"`). Two clients share the
/// same address: one without the cache, one with it.
struct CacheBenchEnv {
    rt: Runtime,
    client_no_cache: Client,
    client_with_cache: Client,
    /// Null-body REQMOD — no embedded HTTP, isolates pure protocol + cache overhead.
    request_empty: Request,
    /// REQMOD with a [`CACHE_BENCH_BODY_SIZE`]-byte HTTP POST body — representative
    /// of typical ICAP deployments (e.g. content inspection).
    request_body: Request,
}

impl CacheBenchEnv {
    fn new() -> Self {
        let port = reserve_port();
        let addr = format!("127.0.0.1:{port}");

        let rt = RtBuilder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("build cache bench runtime");

        rt.block_on(async {
            let server = Server::builder()
                .bind(&addr)
                .route_reqmod(
                    "/reqmod",
                    reqmod_204_cache_handler,
                    Some(
                        ServiceOptions::new()
                            // ISTag must match the handler so reconcile_istag does not
                            // discard the cache entry after each REQMOD response.
                            .with_static_istag("bench-cache")
                            .with_options_ttl(3600),
                    ),
                )
                .build()
                .await
                .expect("build cache benchmark server");

            tokio::spawn(async move {
                let _ = server.run().await;
            });
            wait_port_ready(&addr)
                .await
                .expect("cache benchmark server ready");
        });

        let client_no_cache = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .keep_alive(true)
            .build();

        let client_with_cache = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .keep_alive(true)
            .with_options_cache(
                OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(3600)),
            )
            .build();

        let request_empty = Request::reqmod("/reqmod").allow_204();

        let request_body = Request::reqmod("/reqmod")
            .allow_204()
            .with_http_request(sample_http_request())
            .expect("build cache bench reqmod with body");

        Self {
            rt,
            client_no_cache,
            client_with_cache,
            request_empty,
            request_body,
        }
    }
}

/// Run the three OPTIONS-cache scenarios for a single `request` variant.
///
/// Three variants, always in this order:
/// * `no_cache`            — cache disabled, baseline RPS.
/// * `cache_warm`          — cache pre-warmed once; each iteration pays only for REQMOD.
/// * `cache_cold_per_iter` — cache invalidated before every iteration; OPTIONS + REQMOD per iter.
///
/// `throughput` should be `Throughput::Elements(1)` for null-body requests and
/// `Throughput::Bytes(n)` when there is an HTTP body so Criterion can plot MiB/s.
fn bench_options_cache_group(
    c: &mut Criterion,
    env: &Arc<CacheBenchEnv>,
    group_name: &str,
    request: &Request,
    throughput: Throughput,
) {
    let mut group = c.benchmark_group(group_name);
    group.throughput(throughput);

    // --- baseline: no cache at all ------------------------------------------
    group.bench_function("no_cache", |b| {
        b.iter(|| {
            env.rt.block_on(async {
                let resp = env
                    .client_no_cache
                    .send(request)
                    .await
                    .expect("no-cache send");
                black_box(resp.status_code());
            });
        });
    });

    // --- warm cache: OPTIONS fetched once, then reused ----------------------
    // Each group pre-warms independently so `cache_warm` always starts clean
    // regardless of what the previous group's last iteration left in the cache.
    env.rt.block_on(async {
        let _ = env.client_with_cache.send(request).await.expect("pre-warm");
    });
    group.bench_function("cache_warm", |b| {
        b.iter(|| {
            env.rt.block_on(async {
                let resp = env
                    .client_with_cache
                    .send(request)
                    .await
                    .expect("warm-cache send");
                black_box(resp.status_code());
            });
        });
    });

    // --- cold cache: invalidate before every iteration ----------------------
    group.bench_function("cache_cold_per_iter", |b| {
        b.iter(|| {
            env.rt.block_on(async {
                env.client_with_cache.invalidate_options_cache().await;
                let resp = env
                    .client_with_cache
                    .send(request)
                    .await
                    .expect("cold-cache send");
                black_box(resp.status_code());
            });
        });
    });

    group.finish();
}

fn bench_options_cache_rps(c: &mut Criterion, env: &Arc<CacheBenchEnv>) {
    // Null-body: isolates pure protocol framing + OPTIONS-cache overhead.
    bench_options_cache_group(
        c,
        env,
        "options_cache_rps_empty_body",
        &env.request_empty,
        Throughput::Elements(1),
    );

    // Real body: representative of typical content-inspection workloads.
    bench_options_cache_group(
        c,
        env,
        "options_cache_rps",
        &env.request_body,
        Throughput::Bytes(CACHE_BENCH_BODY_SIZE as u64),
    );
}

fn rps_benches(c: &mut Criterion) {
    let env = Arc::new(BenchEnv::new());
    bench_client_rps(c, &env);
    bench_client_body_rps(c, &env);
    bench_client_streaming_rps(c, &env);
    bench_server_rps(c, &env);
    bench_server_body_rps(c, &env);
    bench_server_rps_parallel(c, &env);
    bench_server_preview_route(c, &env);

    let cache_env = Arc::new(CacheBenchEnv::new());
    bench_options_cache_rps(c, &cache_env);
}

criterion_group!(benches, rps_benches);
criterion_main!(benches);
