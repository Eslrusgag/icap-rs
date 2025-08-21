use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Request as HttpReq, Version, header};
use icap_rs::{
    client::Client,
    error::IcapError,
    options::{IcapMethod, OptionsConfig},
    request::Request as IcapRequest,
    response::{Response, StatusCode},
    server::Server,
};
use once_cell::sync::OnceCell;
use std::time::Duration;
use tokio::runtime::Builder;
use tracing::level_filters::LevelFilter;

const BENCH_HOST: &str = "127.0.0.1";
const BENCH_PORT: u16 = 13451;

static SERVER_ONCE: OnceCell<()> = OnceCell::new();

fn ensure_server_started(rt: &tokio::runtime::Runtime) {
    SERVER_ONCE.get_or_init(|| {
        // quiet logs, but keep warnings if нужно
        let _ = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::WARN)
            .try_init();

        rt.block_on(async {
            // minimal OPTIONS config
            let opts = OptionsConfig::new(
                vec![IcapMethod::ReqMod, IcapMethod::RespMod],
                "benchmark-server-v1.0",
            )
            .with_service("Benchmark Test Server")
            .with_max_connections(10_000)
            .with_options_ttl(3600)
            .add_allow("204")
            .with_preview(1024);

            let server = Server::builder()
                .bind(&format!("{BENCH_HOST}:{BENCH_PORT}"))
                .add_service("benchmark", benchmark_handler)
                .add_options_config("benchmark", opts)
                .build()
                .await
                .expect("build server");

            tokio::spawn(async move {
                let _ = server.run().await;
            });

            // give the listener a moment
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    });
}

async fn benchmark_handler(_req: icap_rs::request::Request) -> Result<Response, IcapError> {
    // Fast-path: no modification needed.
    Ok(Response::new(StatusCode::NoContent204, "No Content")
        .add_header("ISTag", "\"benchmark-server-v1.0\""))
}

fn make_runtime() -> tokio::runtime::Runtime {
    Builder::new_multi_thread().enable_all().build().unwrap()
}

fn make_client() -> Client {
    Client::builder()
        .host(BENCH_HOST)
        .port(BENCH_PORT)
        .keep_alive(true)
        .default_header("User-Agent", "rs-icap-bench/0.1.0")
        .build()
}

fn bench_server_throughput(c: &mut Criterion) {
    let rt = make_runtime();
    ensure_server_started(&rt);

    let client = make_client();
    let mut group = c.benchmark_group("server_throughput");
    group.sample_size(60);
    group.measurement_time(Duration::from_secs(10));

    for &concurrency in &[1usize, 10, 50, 100, 200] {
        group.throughput(Throughput::Elements(concurrency as u64));
        let client_cloned = client.clone();

        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", concurrency),
            &concurrency,
            |b, &concurrent_requests| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::with_capacity(concurrent_requests);

                    for _ in 0..concurrent_requests {
                        let c = client_cloned.clone();

                        let handle = tokio::spawn(async move {
                            // Simple embedded HTTP request
                            let http = HttpReq::builder()
                                .method("GET")
                                .uri("/test")
                                .version(Version::HTTP_11)
                                .header(header::HOST, "bench")
                                .header(header::CONTENT_TYPE, "text/plain")
                                .body(b"test data".to_vec())
                                .unwrap();

                            let icap = IcapRequest::reqmod("/benchmark")
                                .allow_204(true)
                                .with_http_request(http);

                            let _ = c.send(&icap).await;
                        });

                        handles.push(handle);
                    }

                    for h in handles {
                        let _ = h.await;
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_options_requests(c: &mut Criterion) {
    let rt = make_runtime();
    ensure_server_started(&rt);

    let client = make_client();
    let mut group = c.benchmark_group("options_requests");
    group.sample_size(300);

    // Single OPTIONS
    {
        let c1 = client.clone();
        group.bench_function("options_single", |b| {
            b.to_async(&rt).iter(|| async {
                let req = IcapRequest::options("/benchmark");
                let _ = c1.send(&req).await;
            });
        });
    }

    // Parallel OPTIONS
    for &concurrency in &[10usize, 50, 100] {
        let c2 = client.clone();
        group.bench_with_input(
            BenchmarkId::new("options_concurrent", concurrency),
            &concurrency,
            |b, &conc| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::with_capacity(conc);
                    for _ in 0..conc {
                        let cc = c2.clone();
                        handles.push(tokio::spawn(async move {
                            let req = IcapRequest::options("/benchmark");
                            let _ = cc.send(&req).await;
                        }));
                    }
                    for h in handles {
                        let _ = h.await;
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_integration_mixed_load(c: &mut Criterion) {
    let rt = make_runtime();
    ensure_server_started(&rt);

    let client = make_client();
    let mut group = c.benchmark_group("integration_mixed_load");
    group.sample_size(40);
    group.measurement_time(Duration::from_secs(15));

    let c0 = client.clone();
    group.bench_function("mixed_workload", |b| {
        b.to_async(&rt).iter(|| async {
            let mut handles = Vec::new();

            // 30% OPTIONS
            for _ in 0..30 {
                let c = c0.clone();
                handles.push(tokio::spawn(async move {
                    let req = IcapRequest::options("/benchmark");
                    let _ = c.send(&req).await;
                }));
            }

            // 35% REQMOD
            for i in 0..35 {
                let c = c0.clone();
                handles.push(tokio::spawn(async move {
                    let data = format!("request_data_{}", i).into_bytes();
                    let http = HttpReq::builder()
                        .method("POST")
                        .uri("/api/data")
                        .version(Version::HTTP_11)
                        .header(header::HOST, "bench")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(data)
                        .unwrap();

                    let req = IcapRequest::reqmod("/benchmark")
                        .allow_204(true)
                        .with_http_request(http);
                    let _ = c.send(&req).await;
                }));
            }

            for i in 0..35 {
                let c = c0.clone();
                handles.push(tokio::spawn(async move {
                    let http_resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .version(Version::HTTP_11)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(format!("response_data_{}", i).into_bytes())
                        .unwrap();

                    let req = IcapRequest::respmod("/benchmark")
                        .allow_204(true)
                        .with_http_response(http_resp);
                    let _ = c.send(&req).await;
                }));
            }

            for h in handles {
                let _ = h.await;
            }
        });
    });

    group.finish();
}

criterion_group!(
    server_benches,
    bench_server_throughput,
    bench_options_requests,
    bench_integration_mixed_load
);
criterion_main!(server_benches);
