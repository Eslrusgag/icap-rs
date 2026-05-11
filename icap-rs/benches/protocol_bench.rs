use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http::{Request as HttpRequest, Response as HttpResponse, Version};
use icap_rs::{Client, Request, Response, StatusCode};
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

fn bench_response_parse(c: &mut Criterion) {
    let raw_204 = sample_icap_204_response();
    c.bench_function("response_from_raw_204_null_body", |b| {
        b.iter(|| Response::from_raw(black_box(&raw_204)).unwrap());
    });

    {
        let mut group = c.benchmark_group("response_from_raw_200_chunked_http");
        for &body_size in BODY_SIZES {
            let raw = sample_icap_200_response_with_http(body_size);
            group.throughput(Throughput::Bytes(body_size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(body_size), &raw, |b, raw| {
                b.iter(|| Response::from_raw(black_box(raw)).unwrap());
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
            let http_resp = sample_http_response(body_size);
            group.throughput(Throughput::Bytes(body_size as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(body_size),
                &http_resp,
                |b, http_resp| {
                    b.iter(|| {
                        Response::new(StatusCode::OK, "OK")
                            .try_set_istag("bench-200")
                            .unwrap()
                            .with_http_response(black_box(http_resp))
                            .unwrap()
                            .to_raw()
                            .unwrap()
                    });
                },
            );
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
        let mut group = c.benchmark_group("client_get_request_reqmod_preview");
        for &body_size in BODY_SIZES {
            let http_req = sample_http_request(body_size);
            let req = Request::reqmod("scan")
                .allow_204()
                .preview(1024)
                .with_http_request(http_req);
            group.throughput(Throughput::Bytes(body_size as u64));
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
                .with_http_response(http_resp);
            group.throughput(Throughput::Bytes(body_size as u64));
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
        .with_http_request_head(req_head);
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
        .with_http_response_head(resp_head);
    c.bench_function(
        "client_get_request_wire_streaming_respmod_preview_0_ieof",
        |b| {
            b.iter(|| client.get_request_wire(black_box(&req), true).unwrap());
        },
    );
}

fn bench_response_header_mutation(c: &mut Criterion) {
    c.bench_function("response_try_set_istag_and_headers", |b| {
        b.iter(|| {
            Response::no_content()
                .try_set_istag("bench.1")
                .unwrap()
                .try_add_header("Service", "icap-rs benchmark")
                .unwrap()
                .try_add_header("Options-TTL", "3600")
                .unwrap()
        });
    });
}

criterion_group!(
    protocol_benches,
    bench_response_parse,
    bench_response_serialize,
    bench_request_wire_build,
    bench_request_wire_streaming_build,
    bench_response_header_mutation
);
criterion_main!(protocol_benches);
