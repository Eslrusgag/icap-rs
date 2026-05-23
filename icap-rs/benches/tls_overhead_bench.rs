use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::error::IcapResult;
use icap_rs::request::{IncomingRequest, Request};
use icap_rs::response::{Response, StatusCode};
use icap_rs::server::Server;
use icap_rs::{Client, Method};
use std::hint::black_box;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::{Builder as RtBuilder, Runtime};
use tokio::time::sleep;

const CERT_PEM: &str = "certs/server.crt";
const KEY_PEM: &str = "certs/server.key";
const CA_PEM: &str = "certs/ca.pem";
const MAX_NEW_CONNECTION_ITERS_PER_SAMPLE: u64 = 32;

struct BenchEnv {
    rt: Runtime,
    request: Request,
    plain_keepalive: Client,
    tls_keepalive: Client,
    plain_close: Client,
    tls_close: Client,
}

impl BenchEnv {
    fn new() -> Self {
        install_rustls_provider();

        let plain_port = reserve_port();
        let tls_port = reserve_port();
        let plain_addr = format!("127.0.0.1:{plain_port}");
        let tls_addr = format!("127.0.0.1:{tls_port}");

        let rt = RtBuilder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .build()
            .expect("build tokio runtime for bench");

        rt.block_on(async {
            spawn_plain_server(&plain_addr).await;
            spawn_tls_server(&tls_addr).await;
            sleep(Duration::from_millis(80)).await;
        });

        let request = Request::respmod("respmod")
            .allow_204()
            .with_http_response(sample_http_response())
            .expect("build benchmark request");

        let plain_keepalive = Client::builder()
            .host("127.0.0.1")
            .port(plain_port)
            .keep_alive(true)
            .build();
        let tls_keepalive = tls_client(tls_port, true);
        let plain_close = Client::builder()
            .host("127.0.0.1")
            .port(plain_port)
            .keep_alive(false)
            .build();
        let tls_close = tls_client(tls_port, false);

        let env = Self {
            rt,
            request,
            plain_keepalive,
            tls_keepalive,
            plain_close,
            tls_close,
        };
        env.warm_up();
        env
    }

    fn warm_up(&self) {
        for client in [
            &self.plain_keepalive,
            &self.tls_keepalive,
            &self.plain_close,
            &self.tls_close,
        ] {
            self.rt.block_on(async {
                let _ = client.send(&self.request).await.expect("warm up client");
            });
        }
    }
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn spawn_plain_server(addr: &str) {
    let server = Server::builder()
        .bind(addr)
        .route("respmod", [Method::RespMod], fast_204_handler, None)
        .build()
        .await
        .expect("build plain benchmark server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
}

async fn spawn_tls_server(addr: &str) {
    let server = Server::builder()
        .bind(addr)
        .with_tls_from_pem_files(test_data_path(CERT_PEM), test_data_path(KEY_PEM))
        .route("respmod", [Method::RespMod], fast_204_handler, None)
        .build()
        .await
        .expect("build TLS benchmark server");

    tokio::spawn(async move {
        let _ = server.run().await;
    });
}

async fn fast_204_handler(_req: IncomingRequest) -> IcapResult<Response> {
    Response::new(StatusCode::NO_CONTENT, "No Content")
        .try_set_istag("tls-overhead-bench")
        .map(|r| r.add_header("Server", "icap-rs/bench"))
}

fn tls_client(port: u16, keep_alive: bool) -> Client {
    Client::builder()
        .with_uri(&format!("icaps://localhost:{port}/respmod"))
        .expect("valid ICAPS benchmark URI")
        .add_root_ca_pem_file(test_data_path(CA_PEM))
        .expect("load benchmark CA")
        .sni_hostname("localhost")
        .keep_alive(keep_alive)
        .build()
}

fn test_data_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("icap-rs crate has workspace parent")
        .join("test_data")
        .join(relative)
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

fn bench_keepalive(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("tls_overhead_keepalive");
    group.throughput(Throughput::Elements(1));

    for (transport, client) in [
        ("plain_icap", &env.plain_keepalive),
        ("tls_icaps", &env.tls_keepalive),
    ] {
        group.bench_with_input(
            BenchmarkId::new("send_respmod_204", transport),
            client,
            |b, client| {
                b.iter(|| {
                    env.rt.block_on(async {
                        let resp = client.send(&env.request).await.expect("client send");
                        black_box(resp.status_code());
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_new_connection(c: &mut Criterion, env: &Arc<BenchEnv>) {
    let mut group = c.benchmark_group("tls_overhead_new_connection");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(45));
    group.throughput(Throughput::Elements(1));

    for (transport, client) in [
        ("plain_icap", &env.plain_close),
        ("tls_icaps", &env.tls_close),
    ] {
        group.bench_with_input(
            BenchmarkId::new("send_respmod_204", transport),
            client,
            |b, client| {
                b.iter_custom(|iters| {
                    env.rt
                        .block_on(measure_new_connection_iters(client, &env.request, iters))
                });
            },
        );
    }

    group.finish();
}

async fn measure_new_connection_iters(client: &Client, request: &Request, iters: u64) -> Duration {
    let measured_iters = iters.clamp(1, MAX_NEW_CONNECTION_ITERS_PER_SAMPLE);
    let started = Instant::now();

    for _ in 0..measured_iters {
        let resp = client.send(request).await.expect("client send");
        black_box(resp.status_code());
    }

    let scaled_nanos = started
        .elapsed()
        .as_nanos()
        .saturating_mul(u128::from(iters))
        / u128::from(measured_iters);
    Duration::from_nanos(u64::try_from(scaled_nanos).unwrap_or(u64::MAX))
}

fn tls_overhead_benches(c: &mut Criterion) {
    let env = Arc::new(BenchEnv::new());
    bench_keepalive(c, &env);
    bench_new_connection(c, &env);
}

criterion_group!(benches, tls_overhead_benches);
criterion_main!(benches);
