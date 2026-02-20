use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::{Request as HttpRequest, Response as HttpResponse};
use icap_rs::{Client, Request, Response, StatusCode};

fn sample_icap_response_with_http() -> Vec<u8> {
    let body = b"hello world";
    let http_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    );
    let mut embedded = http_head.into_bytes();
    embedded.extend_from_slice(body);

    let header = format!(
        "ICAP/1.0 200 OK\r\nISTag: bench.1\r\nEncapsulated: res-hdr=0, res-body={}\r\n\r\n",
        embedded.len() - body.len()
    );

    let mut raw = header.into_bytes();
    raw.extend_from_slice(&embedded);
    raw
}

fn bench_response_parse(c: &mut Criterion) {
    let raw = sample_icap_response_with_http();
    c.bench_function("response_from_raw_200", |b| {
        b.iter(|| Response::from_raw(black_box(&raw)).unwrap())
    });
}

fn bench_response_serialize(c: &mut Criterion) {
    let http_resp = HttpResponse::builder()
        .status(200)
        .header("Content-Type", "text/plain")
        .body(b"hello world".to_vec())
        .unwrap();

    c.bench_function("response_to_raw_200_with_embedded_http", |b| {
        b.iter(|| {
            Response::new(StatusCode::OK, "OK")
                .try_set_istag("bench.1")
                .unwrap()
                .with_http_response(black_box(&http_resp))
                .unwrap()
                .to_raw()
                .unwrap()
        })
    });
}

fn bench_client_request_build(c: &mut Criterion) {
    let client = Client::builder().host("127.0.0.1").port(1344).build();

    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("http://example.local/upload")
        .header("Host", "example.local")
        .header("Content-Type", "application/octet-stream")
        .body(vec![42u8; 2048])
        .unwrap();

    c.bench_function("client_get_request_reqmod_preview", |b| {
        b.iter(|| {
            let req = Request::reqmod("scan")
                .allow_204()
                .preview(1024)
                .with_http_request(http_req.clone());
            client.get_request(black_box(&req)).unwrap()
        })
    });
}

criterion_group!(
    protocol_benches,
    bench_response_parse,
    bench_response_serialize,
    bench_client_request_build
);
criterion_main!(protocol_benches);
