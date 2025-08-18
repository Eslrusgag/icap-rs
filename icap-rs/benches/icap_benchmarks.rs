use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use icap_rs::client::Request;
use icap_rs::http::HttpMessage;
use icap_rs::{
    Client, IcapMethod, IcapOptionsBuilder, Response, Server, StatusCode, TransferBehavior,
    error::IcapError,
};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Создаёт и запускает тестовый ICAP-сервер на 127.0.0.1:1345 с сервисом /benchmark
async fn create_test_server() -> Result<(), Box<dyn std::error::Error>> {
    let options = IcapOptionsBuilder::new(
        vec![IcapMethod::ReqMod, IcapMethod::RespMod],
        "benchmark-server-v1.0",
    )
    .service("Benchmark Test Server")
    .max_connections(10000)
    .options_ttl(3600)
    .with_current_date()
    .service_id("benchmark")
    .allow_204()
    .preview(1024)
    .default_transfer_behavior(TransferBehavior::Preview)
    .build()?;

    let server = Server::builder()
        .bind("127.0.0.1:1345")
        .add_service("benchmark", benchmark_handler)
        .add_options_config("benchmark", options)
        .build()
        .await?;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // даём серверу подняться
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

async fn benchmark_handler(_request: icap_rs::Request) -> Result<Response, IcapError> {
    // Максимальная скорость — ничего не модифицируем, отвечаем 204
    Ok(Response::new(StatusCode::NoContent204, "No Content")
        .add_header("ISTag", "\"benchmark-server-v1.0\""))
}

fn bench_server_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Поднимаем сервер и создаём один клиент на все замеры
    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });
    let client = Client::new("127.0.0.1", 1345).default_header("User-Agent", "rs-icap-bench/0.1.0");

    let mut group = c.benchmark_group("server_throughput");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    for concurrent_requests in [1, 10, 50, 100, 200].iter() {
        group.throughput(Throughput::Elements(*concurrent_requests as u64));

        let client_cloned = client.clone();
        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", concurrent_requests),
            concurrent_requests,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::with_capacity(concurrency);

                    for _ in 0..concurrency {
                        let client_task = client_cloned.clone();

                        let handle = tokio::spawn(async move {
                            // Вложенный HTTP-запрос
                            let http = HttpMessage::builder("GET /test HTTP/1.1")
                                .header("Content-Type", "text/plain")
                                .body_string("test data")
                                .build();

                            let icap_req = Request::reqmod("/benchmark").allow_204(true).http(http);

                            client_task.send(&icap_req).await
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

fn bench_client_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });
    let client = Client::new("127.0.0.1", 1345).default_header("User-Agent", "rs-icap-bench/0.1.0");

    let mut group = c.benchmark_group("client_latency");
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(5));

    for data_size in [100, 1024, 10_240, 102_400].iter() {
        let test_data = "x".repeat(*data_size);
        group.throughput(Throughput::Bytes(*data_size as u64));

        let client_cloned = client.clone();
        group.bench_with_input(
            BenchmarkId::new("data_size_bytes", data_size),
            &test_data,
            |b, body| {
                b.to_async(&rt).iter(|| async {
                    let http = HttpMessage::builder("POST /upload HTTP/1.1")
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Length", &body.len().to_string())
                        .body_string(body)
                        .build();

                    let icap_req = Request::reqmod("/benchmark").allow_204(true).http(http);

                    let _ = client_cloned.send(&icap_req).await;
                });
            },
        );
    }
    group.finish();
}

fn bench_options_requests(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });
    let client = Client::new("127.0.0.1", 1345).default_header("User-Agent", "rs-icap-bench/0.1.0");

    let mut group = c.benchmark_group("options_requests");
    group.sample_size(500);

    // одиночный OPTIONS
    {
        let client_cloned = client.clone();
        group.bench_function("options_single", |b| {
            b.to_async(&rt).iter(|| async {
                let icap_req = Request::options("/benchmark");
                let _ = client_cloned.send(&icap_req).await;
            });
        });
    }

    // параллельные OPTIONS
    for &concurrent in &[10usize, 50, 100] {
        let client_cloned = client.clone();
        group.bench_with_input(
            BenchmarkId::new("options_concurrent", concurrent),
            &concurrent,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::with_capacity(concurrency);
                    for _ in 0..concurrency {
                        let client_task = client_cloned.clone();
                        let handle = tokio::spawn(async move {
                            let icap_req = Request::options("/benchmark");
                            client_task.send(&icap_req).await
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

fn bench_integration_mixed_load(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });
    let client = Client::new("127.0.0.1", 1345).default_header("User-Agent", "rs-icap-bench/0.1.0");

    let mut group = c.benchmark_group("integration_mixed_load");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    let client_cloned = client.clone();
    group.bench_function("mixed_workload", |b| {
        b.to_async(&rt).iter(|| async {
            let mut handles = Vec::new();

            // 30% OPTIONS
            for _ in 0..30 {
                let c = client_cloned.clone();
                let handle = tokio::spawn(async move {
                    let icap_req = Request::options("/benchmark");
                    c.send(&icap_req).await
                });
                handles.push(handle);
            }

            // 35% REQMOD
            for i in 0..35 {
                let c = client_cloned.clone();
                let handle = tokio::spawn(async move {
                    let test_data = format!("request_data_{}", i);
                    let http = HttpMessage::builder("POST /api/data HTTP/1.1")
                        .header("Content-Type", "application/json")
                        .body_string(&test_data)
                        .build();

                    let icap_req = Request::reqmod("/benchmark").allow_204(true).http(http);

                    c.send(&icap_req).await
                });
                handles.push(handle);
            }

            // 35% RESPMOD
            for i in 0..35 {
                let c = client_cloned.clone();
                let handle = tokio::spawn(async move {
                    let response_data = format!("response_data_{}", i);
                    let http = HttpMessage::builder("HTTP/1.1 200 OK")
                        .header("Content-Type", "application/json")
                        .body_string(&response_data)
                        .build();

                    let icap_req = Request::respmod("/benchmark").allow_204(true).http(http);

                    c.send(&icap_req).await
                });
                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }
        });
    });

    group.finish();
}

fn bench_request_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_parsing");
    group.sample_size(1000);

    let test_request = "REQMOD icap://127.0.0.1:1344/benchmark ICAP/1.0\r\n\
                       Host: 127.0.0.1:1344\r\n\
                       User-Agent: ICAP-Client/1.0\r\n\
                       Allow: 204\r\n\
                       Encapsulated: req-hdr=0, req-body=120\r\n\
                       \r\n\
                       GET /test HTTP/1.1\r\n\
                       Host: example.com\r\n\
                       Content-Type: text/plain\r\n\
                       Content-Length: 9\r\n\
                       \r\n\
                       test data";

    group.throughput(Throughput::Bytes(test_request.len() as u64));

    group.bench_function("parse_icap_request", |b| {
        b.iter(|| {
            // Упрощённая имитация парсинга ICAP-запроса
            let lines: Vec<&str> = test_request.split("\r\n").collect();
            let _first_line = lines[0];
            let mut _headers = std::collections::HashMap::new();

            for line in &lines[1..] {
                if line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once(':') {
                    _headers.insert(key.trim(), value.trim());
                }
            }
        });
    });

    group.finish();
}

fn bench_response_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_creation");
    group.sample_size(2000);

    group.bench_function("create_204_response", |b| {
        b.iter(|| {
            let _response = Response::new(StatusCode::NoContent204, "No Content")
                .add_header("ISTag", "\"benchmark-server-v1.0\"")
                .add_header("Server", "ICAP-RS/1.0");
        });
    });

    group.bench_function("create_200_response_with_body", |b| {
        b.iter(|| {
            let body_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
            let _response = Response::new(StatusCode::Ok200, "OK")
                .add_header("ISTag", "\"benchmark-server-v1.0\"")
                .add_header("Encapsulated", "res-hdr=0, res-body=100")
                .with_body(body_data);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_server_throughput,
    bench_client_latency,
    bench_options_requests,
    bench_integration_mixed_load,
    bench_request_parsing,
    bench_response_creation
);

criterion_main!(benches);
