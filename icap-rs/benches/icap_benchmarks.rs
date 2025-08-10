use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use icap_rs::http::HttpSession;
use icap_rs::{
    IcapClient, IcapMethod, IcapOptionsBuilder, IcapRequest, IcapResponse, IcapServer,
    IcapStatusCode, TransferBehavior, error::IcapError,
};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Создает простой тестовый сервер
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

    let server = IcapServer::builder()
        .bind("127.0.0.1:1345")
        .add_service("benchmark", benchmark_handler)
        .add_options_config("benchmark", options)
        .build()
        .await?;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

async fn benchmark_handler(request: IcapRequest) -> Result<IcapResponse, IcapError> {
    match request.method.as_str() {
        "REQMOD" | "RESPMOD" => {
            // Возвращаем 204 No Content для максимальной скорости
            Ok(
                IcapResponse::new(IcapStatusCode::NoContent204, "No Content")
                    .add_header("ISTag", "\"benchmark-server-v1.0\""),
            )
        }
        "OPTIONS" => {
            // Обрабатывается автоматически сервером
            Ok(IcapResponse::new(IcapStatusCode::Ok200, "OK"))
        }
        _ => Ok(IcapResponse::new(
            IcapStatusCode::MethodNotAllowed405,
            "Method Not Allowed",
        )),
    }
}

fn bench_server_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Запускаем сервер
    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });

    let mut group = c.benchmark_group("server_throughput");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(10));

    // Различные размеры нагрузки
    for concurrent_requests in [1, 10, 50, 100, 200].iter() {
        group.throughput(Throughput::Elements(*concurrent_requests as u64));

        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", concurrent_requests),
            concurrent_requests,
            |b, &concurrent_requests| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for _ in 0..concurrent_requests {
                        let handle = tokio::spawn(async {
                            let http_session = HttpSession::new("GET", "/test")
                                .add_header("Content-Type", "text/plain")
                                .with_body_string("test data");

                            let client = IcapClient::builder()
                                .set_host("127.0.0.1")
                                .set_port(1345)
                                .set_service("benchmark")
                                .set_icap_method("REQMOD")
                                .with_http_session(http_session)
                                .build();

                            client.send().await
                        });
                        handles.push(handle);
                    }

                    // Ждем завершения всех запросов
                    for handle in handles {
                        let _ = handle.await;
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_client_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Запускаем сервер
    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });

    let mut group = c.benchmark_group("client_latency");
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(5));

    // Различные размеры данных
    for data_size in [100, 1024, 10240, 102400].iter() {
        let test_data = "x".repeat(*data_size);

        group.throughput(Throughput::Bytes(*data_size as u64));

        group.bench_with_input(
            BenchmarkId::new("data_size_bytes", data_size),
            &test_data,
            |b, test_data| {
                b.to_async(&rt).iter(|| async {
                    let http_session = HttpSession::new("POST", "/upload")
                        .add_header("Content-Type", "application/octet-stream")
                        .add_header("Content-Length", &test_data.len().to_string())
                        .with_body_string(test_data);

                    let client = IcapClient::builder()
                        .set_host("127.0.0.1")
                        .set_port(1345)
                        .set_service("benchmark")
                        .set_icap_method("REQMOD")
                        .with_http_session(http_session)
                        .build();

                    let _ = client.send().await;
                });
            },
        );
    }
    group.finish();
}

fn bench_options_requests(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Запускаем сервер
    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });

    let mut group = c.benchmark_group("options_requests");
    group.sample_size(500);

    group.bench_function("options_single", |b| {
        b.to_async(&rt).iter(|| async {
            let client = IcapClient::builder()
                .set_host("127.0.0.1")
                .set_port(1345)
                .set_service("benchmark")
                .set_icap_method("OPTIONS")
                .build();

            let _ = client.send().await;
        });
    });

    // Параллельные OPTIONS запросы
    for concurrent in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("options_concurrent", concurrent),
            concurrent,
            |b, &concurrent| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for _ in 0..concurrent {
                        let handle = tokio::spawn(async {
                            let client = IcapClient::builder()
                                .set_host("127.0.0.1")
                                .set_port(1345)
                                .set_service("benchmark")
                                .set_icap_method("OPTIONS")
                                .build();

                            client.send().await
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        let _ = handle.await;
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_integration_mixed_load(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Запускаем сервер
    rt.block_on(async {
        create_test_server()
            .await
            .expect("Failed to start test server");
    });

    let mut group = c.benchmark_group("integration_mixed_load");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("mixed_workload", |b| {
        b.to_async(&rt).iter(|| async {
            let mut handles = Vec::new();

            // 30% OPTIONS запросов
            for _ in 0..30 {
                let handle = tokio::spawn(async {
                    let client = IcapClient::builder()
                        .set_host("127.0.0.1")
                        .set_port(1345)
                        .set_service("benchmark")
                        .set_icap_method("OPTIONS")
                        .build();
                    client.send().await
                });
                handles.push(handle);
            }

            // 35% REQMOD запросов
            for i in 0..35 {
                let handle = tokio::spawn(async move {
                    let test_data = format!("request_data_{}", i);
                    let http_session = HttpSession::new("POST", "/api/data")
                        .add_header("Content-Type", "application/json")
                        .with_body_string(&test_data);

                    let client = IcapClient::builder()
                        .set_host("127.0.0.1")
                        .set_port(1345)
                        .set_service("benchmark")
                        .set_icap_method("REQMOD")
                        .with_http_session(http_session)
                        .build();
                    client.send().await
                });
                handles.push(handle);
            }

            // 35% RESPMOD запросов
            for i in 0..35 {
                let handle = tokio::spawn(async move {
                    let response_data = format!("response_data_{}", i);
                    let http_session = HttpSession::new("GET", "/api/response")
                        .add_header("Accept", "application/json")
                        .with_body_string(&response_data);

                    let client = IcapClient::builder()
                        .set_host("127.0.0.1")
                        .set_port(1345)
                        .set_service("benchmark")
                        .set_icap_method("RESPMOD")
                        .with_http_session(http_session)
                        .build();
                    client.send().await
                });
                handles.push(handle);
            }

            // Ждем завершения всех запросов
            for handle in handles {
                let _ = handle.await;
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
                       Encapsulated: req-hdr=0, null-body=120\r\n\
                       \r\n\
                       GET /test HTTP/1.1\r\n\
                       Host: example.com\r\n\
                       Content-Type: text/plain\r\n\
                       Content-Length: 11\r\n\
                       \r\n\
                       test data\r\n";

    group.throughput(Throughput::Bytes(test_request.len() as u64));

    group.bench_function("parse_icap_request", |b| {
        b.iter(|| {
            // Имитируем парсинг ICAP запроса
            let lines: Vec<&str> = test_request.lines().collect();
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
            let _response = IcapResponse::new(IcapStatusCode::NoContent204, "No Content")
                .add_header("ISTag", "\"benchmark-server-v1.0\"")
                .add_header("Server", "ICAP-RS/1.0");
        });
    });

    group.bench_function("create_200_response_with_body", |b| {
		b.iter(|| {
			let body_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
			let _response = IcapResponse::new(IcapStatusCode::Ok200, "OK")
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
