use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Request as HttpRequest, Response as HttpResponse, Version};
use icap_rs::{Client, ParsedResponse, Request, Response, StatusCode};
use std::hint::black_box;

const BODY_SIZES: &[usize] = &[0, 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

fn chunked_icap_entity(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    out.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

fn sample_http_response(body_size: usize) -> HttpResponse<Vec<u8>> {
    HttpResponse::builder()
        .status(200)
        .version(Version::HTTP_11)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", body_size.to_string())
        .body(vec![42u8; body_size])
        .unwrap()
}

fn sample_http_request(body_size: usize) -> HttpRequest<Vec<u8>> {
    HttpRequest::builder()
        .method("POST")
        .uri("http://example.local/upload")
        .version(Version::HTTP_11)
        .header("Host", "example.local")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", body_size.to_string())
        .body(vec![42u8; body_size])
        .unwrap()
}

fn sample_icap_204_response() -> Vec<u8> {
    b"ICAP/1.0 204 No Content\r\nISTag: \"bench-204\"\r\nEncapsulated: null-body=0\r\n\r\n".to_vec()
}

fn sample_icap_200_response_with_http(body_size: usize) -> Vec<u8> {
    let body = vec![42u8; body_size];
    let http_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {body_size}\r\nContent-Type: application/octet-stream\r\n\r\n"
    );
    let http_head = http_head.into_bytes();

    let header = format!(
        "ICAP/1.0 200 OK\r\nISTag: \"bench-200\"\r\nEncapsulated: res-hdr=0, res-body={}\r\n\r\n",
        http_head.len()
    );

    let mut raw = header.into_bytes();
    raw.extend_from_slice(&http_head);
    raw.extend_from_slice(&chunked_icap_entity(&body));
    raw
}

// RFC 3507 206 Partial Content with use-original-body=0 (header-only adaptation).
// This is the most common 206 pattern: server passes through the original body unchanged.
fn sample_icap_206_response_head_only() -> Vec<u8> {
    let http_head = b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nContent-Type: application/octet-stream\r\n\r\n";
    let header = format!(
        "ICAP/1.0 206 Partial Content\r\nISTag: \"bench-206\"\r\nEncapsulated: res-hdr=0, res-body={}\r\n\r\n",
        http_head.len()
    );
    let mut raw = header.into_bytes();
    raw.extend_from_slice(http_head);
    raw.extend_from_slice(b"0; use-original-body=0\r\n\r\n");
    raw
}

fn bench_response_parse(c: &mut Criterion) {
    let raw_204 = sample_icap_204_response();
    c.bench_function("response_from_raw_204_null_body", |b| {
        b.iter(|| ParsedResponse::from_raw(black_box(&raw_204)).unwrap());
    });

    // 206 with use-original-body: a distinct parsing path (zero-chunk extension detection).
    let raw_206 = sample_icap_206_response_head_only();
    c.bench_function("response_from_raw_206_use_original_body", |b| {
        b.iter(|| ParsedResponse::from_raw(black_box(&raw_206)).unwrap());
    });

    {
        let mut group = c.benchmark_group("response_from_raw_200_chunked_http");
        for &body_size in BODY_SIZES {
            let raw = sample_icap_200_response_with_http(body_size);
            // body_size=0 produces 0 bytes/s (meaningless); skip throughput annotation.
            if body_size > 0 {
                group.throughput(Throughput::Bytes(body_size as u64));
            }
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &raw, |b, raw| {
                b.iter(|| ParsedResponse::from_raw(black_box(raw)).unwrap());
            });
        }
        group.finish();
    }
}

fn bench_response_serialize(c: &mut Criterion) {
    let resp_204 = Response::no_content_with_istag("bench-204").unwrap();
    c.bench_function("response_to_raw_204_null_body", |b| {
        b.iter(|| black_box(&resp_204).to_raw().unwrap());
    });

    let http_head = HttpResponse::builder()
        .status(200)
        .version(Version::HTTP_11)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", "65536")
        .body(())
        .unwrap();
    let resp_206 = Response::partial_content_with_istag("bench-206")
        .unwrap()
        .with_http_response_head_and_original_body(&http_head, 1024)
        .unwrap();
    c.bench_function("response_to_raw_206_use_original_body", |b| {
        b.iter(|| black_box(&resp_206).to_raw().unwrap());
    });

    {
        let mut group = c.benchmark_group("response_to_raw_200_with_embedded_http");
        for &body_size in BODY_SIZES {
            // Pre-build the response outside the measurement loop so that only
            // to_raw() (ICAP header serialization + chunked body encoding) is measured.
            // with_http_response() copies the full body on every call, which would
            // inflate measurements for large sizes if done inside b.iter().
            let http_resp = sample_http_response(body_size);
            let resp = Response::new(StatusCode::OK, "OK")
                .try_set_istag("bench-200")
                .unwrap()
                .with_http_response(&http_resp)
                .unwrap();
            if body_size > 0 {
                group.throughput(Throughput::Bytes(body_size as u64));
            }
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &resp, |b, resp| {
                b.iter(|| black_box(resp).to_raw().unwrap());
            });
        }
        group.finish();
    }
}

fn bench_request_wire_build(c: &mut Criterion) {
    let client = Client::builder().host("127.0.0.1").port(1344).build();

    let options = Request::options("scan");
    c.bench_function("client_get_request_options", |b| {
        b.iter(|| client.get_request(black_box(&options)).unwrap());
    });

    {
        // Preview requests: only min(body_size, preview_size) bytes appear on the wire.
        // Throughput is annotated against actual wire bytes so the metric is accurate.
        // For body_size > 1024, wire size is flat (preview truncation), which correctly
        // shows that serialization cost is O(preview_size) rather than O(body_size).
        let mut group = c.benchmark_group("client_get_request_reqmod_preview");
        for &body_size in BODY_SIZES {
            let http_req = sample_http_request(body_size);
            let req = Request::reqmod("scan")
                .allow_204()
                .preview(1024)
                .with_http_request(http_req)
                .unwrap();
            let wire_len = client.get_request(&req).unwrap().len() as u64;
            if wire_len > 0 {
                group.throughput(Throughput::Bytes(wire_len));
            }
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &req, |b, req| {
                b.iter(|| client.get_request(black_box(req)).unwrap());
            });
        }
        group.finish();
    }

    {
        // Full body serialization: no preview, entire HTTP body is chunked into wire bytes.
        // Demonstrates O(body_size) scaling of the request encoding path.
        let mut group = c.benchmark_group("client_get_request_reqmod_full_body");
        for &body_size in BODY_SIZES {
            let http_req = sample_http_request(body_size);
            let req = Request::reqmod("scan")
                .allow_204()
                .with_http_request(http_req)
                .unwrap();
            if body_size > 0 {
                group.throughput(Throughput::Bytes(body_size as u64));
            }
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &req, |b, req| {
                b.iter(|| client.get_request(black_box(req)).unwrap());
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("client_get_request_respmod");
        for &body_size in BODY_SIZES {
            let http_resp = sample_http_response(body_size);
            let req = Request::respmod("scan")
                .allow_204()
                .with_http_response(http_resp)
                .unwrap();
            if body_size > 0 {
                group.throughput(Throughput::Bytes(body_size as u64));
            }
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &req, |b, req| {
                b.iter(|| client.get_request(black_box(req)).unwrap());
            });
        }
        group.finish();
    }
}

fn bench_request_wire_streaming_build(c: &mut Criterion) {
    let client = Client::builder().host("127.0.0.1").port(1344).build();

    let req_head = HttpRequest::builder()
        .method("POST")
        .uri("http://example.local/upload")
        .version(Version::HTTP_11)
        .header("Host", "example.local")
        .header("Content-Type", "application/octet-stream")
        .body(())
        .unwrap();
    let req = Request::reqmod("scan")
        .preview(0)
        .with_http_request_head(req_head)
        .unwrap();
    c.bench_function("client_get_request_wire_streaming_reqmod_preview_0", |b| {
        b.iter(|| client.get_request_wire(black_box(&req), true).unwrap());
    });

    let resp_head = HttpResponse::builder()
        .status(200)
        .version(Version::HTTP_11)
        .header("Content-Type", "application/octet-stream")
        .body(())
        .unwrap();
    let req = Request::respmod("scan")
        .preview(0)
        .preview_ieof()
        .with_http_response_head(resp_head)
        .unwrap();
    c.bench_function(
        "client_get_request_wire_streaming_respmod_preview_0_ieof",
        |b| {
            b.iter(|| client.get_request_wire(black_box(&req), true).unwrap());
        },
    );
}

criterion_group!(
    protocol_benches,
    bench_response_parse,
    bench_response_serialize,
    bench_request_wire_build,
    bench_request_wire_streaming_build,
);
criterion_main!(protocol_benches);
