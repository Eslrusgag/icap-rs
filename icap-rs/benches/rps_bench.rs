use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::error::IcapResult;
use icap_rs::request::Request;
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::{Client, Method};
use std::hint::black_box;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::{Builder as RtBuilder, Runtime};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};

const CONCURRENCY_LEVELS: &[usize] = &[1, 4, 16];

struct BenchEnv {
    rt: Runtime,
    client: Client,
    request: Request,
    wire_request: Vec<u8>,
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
                .route("respmod", [Method::RespMod], fast_204_handler, None)
                .build()
                .await
                .expect("build benchmark server");

            tokio::spawn(async move {
                let _ = server.run().await;
            });
            sleep(Duration::from_millis(60)).await;
        });

        let client = Client::builder()
            .host("127.0.0.1")
            .port(port)
            .keep_alive(true)
            .build();

        let request = Request::respmod("respmod")
            .allow_204()
            .with_http_response(sample_http_response());

        let wire_request = client
            .get_request(&request)
            .expect("build wire request for raw bench");

        Self {
            rt,
            client,
            request,
            wire_request,
            addr,
        }
    }
}

async fn fast_204_handler(_req: Request) -> IcapResult<Response> {
    Response::new(StatusCode::NO_CONTENT, "No Content")
        .try_set_istag("bench-204")
        .map(|r| r.add_header("Server", "icap-rs/bench"))
}

fn sample_http_response() -> HttpResponse<Vec<u8>> {
    let body = b"hello".to_vec();
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/plain")
        .header("Content-Length", body.len().to_string())
        .body(body)
        .expect("build sample http response")
}

fn reserve_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

fn headers_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
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

async fn connect_with_retry(addr: &str) -> IcapResult<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
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
            read_icap_headers(&mut socket).await
        });
    }
    while let Some(joined) = set.join_next().await {
        let resp = joined.map_err(|e| format!("raw task join error: {e}"))??;
        black_box(resp);
    }
    Ok(())
}

fn bench_client_rps(c: &mut Criterion, env: Arc<BenchEnv>) {
    let mut group = c.benchmark_group("client_rps");
    group.throughput(Throughput::Elements(1));
    group.bench_with_input(
        BenchmarkId::new("send_respmod_204_keepalive", 1),
        &1usize,
        |b, _| {
            b.iter(|| {
                env.rt.block_on(async {
                    let resp = env.client.send(&env.request).await.expect("client send");
                    black_box(resp.status_code);
                });
            });
        },
    );
    group.finish();
}

fn bench_server_rps(c: &mut Criterion, env: Arc<BenchEnv>) {
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
                    socket.write_all(&env.wire_request).await?;
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

fn bench_server_rps_parallel(c: &mut Criterion, env: Arc<BenchEnv>) {
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
                let wire = Arc::new(env.wire_request.clone());
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

fn rps_benches(c: &mut Criterion) {
    let env = Arc::new(BenchEnv::new());
    bench_client_rps(c, Arc::clone(&env));
    bench_server_rps(c, Arc::clone(&env));
    bench_server_rps_parallel(c, env);
}

criterion_group!(benches, rps_benches);
criterion_main!(benches);
