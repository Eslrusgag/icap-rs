use http::{HeaderValue, Request as HttpRequest, header};
use icap_rs::{
    Body, EmbeddedHttp, Method, Request, Response, StatusCode,
    server::{Server, options::ServiceOptions},
};
use std::{str, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const ISTAG: &str = "it-scan-1.0";

fn find_double_crlf(hay: &[u8]) -> Option<usize> {
    hay.windows(4).position(|w| w == b"\r\n\r\n")
}

fn icap_status_code(buf: &[u8]) -> Option<u16> {
    let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = &buf[..line_end];
    // "ICAP/1.0 204 No Content"
    let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    if parts.len() >= 2 && parts[0].starts_with(b"ICAP/") {
        let code = std::str::from_utf8(parts[1]).ok()?.parse::<u16>().ok()?;
        Some(code)
    } else {
        None
    }
}

fn http_content_length(http_head: &[u8]) -> Option<usize> {
    let mut len: Option<usize> = None;
    for line in http_head.split(|&b| b == b'\n') {
        let line = if let Some(b) = line.strip_suffix(b"\r") {
            b
        } else {
            line
        };
        let lower = line
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if lower.starts_with(b"content-length:") {
            let v = &line[b"Content-Length:".len()..].trim_ascii();
            len = std::str::from_utf8(v).ok()?.trim().parse::<usize>().ok();
            break;
        }
    }
    len
}

async fn start_server(addr: &str) {
    let server = Server::builder()
        .bind(addr)
        .route(
            "scan",
            [Method::ReqMod],
            |req: Request| async move {
                let mut maybe_len = None::<usize>;
                if let Some(EmbeddedHttp::Req { head: _, body }) = &req.embedded {
                    match body {
                        Body::Full { reader } => {
                            maybe_len = Some(reader.len());
                        }
                        Body::Preview { .. } => {}
                        Body::Empty => maybe_len = Some(0),
                    }
                }

                let preview_n = req.preview_size.unwrap_or(0);
                if let Some(total_len) = maybe_len {
                    if total_len <= preview_n {
                        return Ok(Response::no_content().try_set_istag(ISTAG)?);
                    }
                }

                if let Some(EmbeddedHttp::Req { head, body }) = req.embedded {
                    if let Body::Full { reader } = body {
                        let mut headers = head.headers().clone();
                        headers.remove(header::TRANSFER_ENCODING);
                        headers.remove(header::TE);
                        headers.insert(
                            header::CONTENT_LENGTH,
                            HeaderValue::from_str(&reader.len().to_string()).unwrap(),
                        );

                        let mut builder = HttpRequest::builder()
                            .method(head.method().clone())
                            .uri(head.uri().clone())
                            .version(head.version());

                        if let Some(h) = builder.headers_mut() {
                            *h = headers;
                        }

                        let http_req = builder
                            .body(reader)
                            .map_err(|e| format!("build echo http::Request: {e}"))?;

                        let resp = Response::new(StatusCode::OK, "OK")
                            .try_set_istag(ISTAG)?
                            .with_http_request(&http_req)?;
                        return Ok(resp);
                    }
                }

                Ok(Response::no_content().try_set_istag(ISTAG)?)
            },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_preview(2048)
                    .add_allow("204"),
            ),
        )
        .default_service("scan")
        .build()
        .await
        .expect("server build");

    tokio::spawn(async move {
        server.run().await.expect("server run");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn icap_reqmod_with_preview(
    host_port: &str,
    service: &str,
    preview_n: usize,
    http_head: &str,
    preview_bytes: &[u8],
    tail_bytes: Option<&[u8]>,
    ieof: bool,
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(host_port).await.expect("connect");

    let http_head_bytes = http_head.as_bytes();
    let req_body_off = http_head_bytes.len();

    let icap = format!(
        "REQMOD icap://{}/{} ICAP/1.0\r\n\
         Host: {}\r\n\
         Encapsulated: req-hdr=0, req-body={}\r\n\
         Preview: {}\r\n\
         \r\n",
        host_port, service, host_port, req_body_off, preview_n
    );

    stream
        .write_all(icap.as_bytes())
        .await
        .expect("write icap head");
    stream
        .write_all(http_head_bytes)
        .await
        .expect("write http head");

    let mut buf = Vec::new();
    buf.extend_from_slice(format!("{:X}\r\n", preview_bytes.len()).as_bytes());
    buf.extend_from_slice(preview_bytes);
    buf.extend_from_slice(b"\r\n");

    if let Some(tail) = tail_bytes {
        buf.extend_from_slice(format!("{:X}\r\n", tail.len()).as_bytes());
        buf.extend_from_slice(tail);
        buf.extend_from_slice(b"\r\n");
    }

    if ieof {
        buf.extend_from_slice(b"0; ieof\r\n\r\n");
    } else {
        buf.extend_from_slice(b"0\r\n\r\n");
    }

    stream.write_all(&buf).await.expect("write icap body");

    stream.flush().await.ok();
    stream.set_nodelay(true).ok();

    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        let mut tmp = [0u8; 8192];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    resp.extend_from_slice(&tmp[..n]);
                    if let Some(h_end) = find_double_crlf(&resp) {
                        if let Some(code) = icap_status_code(&resp) {
                            if code == 204 {
                                break;
                            }
                            if let Some(off2) = find_double_crlf(&resp[h_end + 4..]) {
                                let http_head = &resp[h_end + 4..h_end + 4 + off2];
                                if let Some(cl) = http_content_length(http_head) {
                                    let have = resp.len() - (h_end + 4 + off2 + 4);
                                    if have >= cl {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    })
    .await;

    let code = icap_status_code(&resp).expect("no icap code");
    (code, resp)
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_ieof_fast204() {
    let addr = "127.0.0.1:13440";
    start_server(addr).await;

    let body = b"ping";
    let http_head = format!(
        "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );

    let (code, _resp) =
        icap_reqmod_with_preview(addr, "scan", body.len(), &http_head, body, None, true).await;

    assert_eq!(
        code, 204,
        "server should return 204 when body fits into preview (ieof)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_non_ieof_full_body_roundtrip() {
    let addr = "127.0.0.1:13441";
    start_server(addr).await;

    let preview = b"abcd";
    let tail = b"efghij";
    let total_body = [preview.as_ref(), tail.as_ref()].concat();

    let http_head = format!(
        "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
        total_body.len()
    );

    let (code, resp) = icap_reqmod_with_preview(
        addr,
        "scan",
        preview.len(),
        &http_head,
        preview,
        Some(tail),
        false,
    )
    .await;

    assert_eq!(
        code, 200,
        "server should return 200 OK when body exceeds preview"
    );

    let h1 = find_double_crlf(&resp).expect("icap hdr end");
    let resp_after_icap = &resp[h1 + 4..];
    let h2 = find_double_crlf(resp_after_icap).expect("http hdr end");
    let http_head_bytes = &resp_after_icap[..h2];
    let http_body = &resp_after_icap[h2 + 4..];

    let cl = http_content_length(http_head_bytes).expect("content-length");
    assert!(
        http_body.len() >= cl,
        "not enough bytes for http body (have {}, need {})",
        http_body.len(),
        cl
    );
    assert_eq!(
        &http_body[..cl],
        total_body.as_slice(),
        "echoed HTTP body mismatch"
    );
}
