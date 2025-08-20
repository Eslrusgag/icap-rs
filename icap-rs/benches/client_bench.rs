use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use http::{Request as HttpReq, Version, header};
use icap_rs::{
    client::Client,
    request::Request as IcapRequest,
    response::{Response, StatusCode},
};

fn extract_headers_text(wire: &[u8]) -> &str {
    let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    std::str::from_utf8(&wire[..end]).unwrap()
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
    group.bench_function("split_headers_kv", |b| {
        b.iter(|| {
            // Primitive, allocation-light parsing used just for baseline
            let mut it = test_request.split("\r\n");
            let _start_line = it.next().unwrap();
            let mut _map = std::collections::HashMap::new();
            for line in it.by_ref() {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    _map.insert(k.trim(), v.trim());
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
            let _ = Response::new(StatusCode::NoContent204, "No Content")
                .add_header("ISTag", "\"benchmark-server-v1.0\"")
                .add_header("Server", "ICAP-RS/1.0");
        });
    });

    group.bench_function("create_200_response_with_body", |b| {
		b.iter(|| {
			// Body is raw HTTP response bytes as required by ICAP
			let body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
			let _ = Response::new(StatusCode::Ok200, "OK")
				.add_header("ISTag", "\"benchmark-server-v1.0\"")
				.add_header("Encapsulated", "res-hdr=0, res-body=100")
				.with_body(body);
		});
	});

    group.finish();
}

fn bench_wire_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_building");
    group.sample_size(800);

    let client = Client::builder()
        .host("icap.example")
        .port(1344)
        .default_header("x-trace-id", "bench-123")
        .keep_alive(true)
        .build();

    // REQMOD with small preview
    group.bench_function("reqmod_preview_4", |b| {
        b.iter(|| {
            let http = HttpReq::builder()
                .method("POST")
                .uri("/scan")
                .version(Version::HTTP_11)
                .header(header::HOST, "app")
                .header(header::CONTENT_LENGTH, "7")
                .body(b"PAYLOAD".to_vec())
                .unwrap();

            let icap = IcapRequest::reqmod("icap/full")
                .preview(4)
                .allow_204(true)
                .icap_header("x-foo", "bar")
                .with_http_request(http);

            let wire = client.get_request_wire(&icap, false).unwrap();
            let _head = extract_headers_text(&wire);
        });
    });

    // REQMOD with Preview: 0 (appends zero-chunk on the wire)
    group.bench_function("reqmod_preview_0", |b| {
        b.iter(|| {
            let http = HttpReq::builder()
                .method("POST")
                .uri("/scan")
                .version(Version::HTTP_11)
                .header(header::HOST, "x")
                .body(Vec::<u8>::new())
                .unwrap();

            let icap = IcapRequest::reqmod("icap/full")
                .preview(0)
                .with_http_request(http);

            let wire = client.get_request_wire(&icap, false).unwrap();
            let _ = std::str::from_utf8(&wire).unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    client_benches,
    bench_request_parsing,
    bench_response_creation,
    bench_wire_building
);
criterion_main!(client_benches);
