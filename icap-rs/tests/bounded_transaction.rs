//! Independent wire fixtures: these tests do not use the convenience server,
//! request serializer, response parser or chunk encoder as their oracle.
use icap_rs::streaming::{Error, Method, PreviewOutcome, RequestHead, Transaction, Transport};
use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("wire fixture unexpectedly blocked"),
    }
}

struct Peer {
    input: Vec<u8>,
    output: Vec<u8>,
    cursor: usize,
    fragment: usize,
}

impl Peer {
    fn new(response: impl Into<Vec<u8>>) -> Self {
        Self {
            input: response.into(),
            output: Vec::new(),
            cursor: 0,
            fragment: usize::MAX,
        }
    }
}

impl Transport for Peer {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out
            .len()
            .min(self.input.len() - self.cursor)
            .min(self.fragment);
        out[..n].copy_from_slice(&self.input[self.cursor..self.cursor + n]);
        self.cursor += n;
        Ok(n)
    }
    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(self.fragment);
        self.output.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const HTTP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
const NO_CONTENT: &[u8] =
    b"ICAP/1.0 204 No Content\r\nISTag: \"v1\"\r\nEncapsulated: null-body=0\r\n\r\n";

// A deployed peer's header shape, with a portable example identity. This is
// a compatibility case: RFC 3507 requires Encapsulated on every message.
const BARE_NO_CONTENT: &[u8] = b"ICAP/1.0 204 Unmodified\r\nServer: C-ICAP/0.5.10\r\nConnection: close\r\nISTag: \"example-signature\"\r\n\r\n";

const fn request(preview: Option<u64>) -> RequestHead<'static> {
    RequestHead {
        method: Method::RespMod,
        uri: "icap://example.test:1344/process?mode=scan",
        host: "example.test:1344",
        headers: &[("Authorization", "Basic dXNlcjpwYXNz"), ("Allow", "204")],
        http_request: b"",
        http_response: HTTP,
        preview,
    }
}

const fn options() -> RequestHead<'static> {
    RequestHead {
        method: Method::Options,
        http_response: b"",
        preview: None,
        ..request(None)
    }
}

const fn method_request(method: Method, preview: Option<u64>) -> RequestHead<'static> {
    match method {
        Method::Options => options(),
        Method::ReqMod => RequestHead {
            method,
            http_request: b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            http_response: b"",
            ..request(preview)
        },
        Method::RespMod => request(preview),
    }
}

async fn reject_wrong_respmod_body(body: &str) {
    for fragment in [1, 7, usize::MAX] {
        // Normal final, preview-zero early final, and final after Continue.
        for path in 0..3 {
            for bytes in [b"0\r\n\r\n".as_slice(), b"3\r\nabc\r\n0\r\n\r\n".as_slice()] {
                let mut wire = Vec::new();
                if path == 2 {
                    wire.extend_from_slice(b"ICAP/1.0 100 Continue\r\n\r\n");
                }
                wire.extend_from_slice(&response_body(&format!("{body}=0"), bytes));
                let mut peer = Peer::new(wire);
                peer.fragment = fragment;
                let mut head = [0; 1024];
                let mut line = [0; 128];
                let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                tx.start(request(if path == 0 { None } else { Some(0) }))
                    .await
                    .unwrap();
                let result = if path == 1 {
                    tx.finish_preview(false).await.map(|_| ())
                } else {
                    if path == 2 {
                        assert_eq!(
                            tx.finish_preview(false).await.unwrap(),
                            PreviewOutcome::Continue
                        );
                    }
                    tx.finish_body().await.unwrap();
                    tx.read_response().await
                };
                if result.is_ok() {
                    tx.discard_body(&mut [0; 3]).await.unwrap();
                    panic!(
                        "accepted and completely drained RESPMOD {body}, path={path}, fragment={fragment}"
                    );
                }
                assert!(matches!(
                    result,
                    Err(Error::Protocol("encapsulated entity does not match method"))
                ));
                assert!(tx.response().is_none());
                assert!(matches!(
                    tx.read_body(&mut [0; 3]).await,
                    Err(Error::InvalidState)
                ));
            }
        }
    }
}

#[test]
fn respmod_rejects_request_body() {
    run(reject_wrong_respmod_body("req-body"));
}

#[test]
fn respmod_rejects_options_body() {
    run(reject_wrong_respmod_body("opt-body"));
}

#[test]
fn response_entity_method_matrix() {
    run(async {
        let req = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let res = b"HTTP/1.1 403 Forbidden\r\n\r\n";
        // Each row lists the accepted terminals for: no HTTP head, request
        // head, response head, both heads. This oracle is independent of the
        // library's internal entity enum and matching implementation.
        let cases: &[(Method, [&[&str]; 4])] = &[
            (Method::Options, [&["opt-body", "null-body"], &[], &[], &[]]),
            (
                Method::ReqMod,
                [
                    &["req-body", "res-body", "null-body"],
                    &["req-body", "null-body"],
                    &["res-body", "null-body"],
                    &[],
                ],
            ),
            (
                Method::RespMod,
                [
                    &["res-body", "null-body"],
                    &[],
                    &["res-body", "null-body"],
                    &[],
                ],
            ),
        ];
        for &(method, allowed) in cases {
            for (head_kind, terminals) in allowed.into_iter().enumerate() {
                let mut prefix = Vec::new();
                let mut parts = String::new();
                if head_kind == 1 || head_kind == 3 {
                    parts.push_str("req-hdr=0, ");
                    prefix.extend_from_slice(req);
                }
                if head_kind == 2 || head_kind == 3 {
                    write!(parts, "res-hdr={}, ", prefix.len()).unwrap();
                    prefix.extend_from_slice(res);
                }
                for terminal in ["req-body", "res-body", "opt-body", "null-body"] {
                    for fragment in [1, usize::MAX] {
                        let mut bytes = prefix.clone();
                        if terminal != "null-body" {
                            bytes.extend_from_slice(b"3\r\nabc\r\n0\r\n\r\n");
                        }
                        let wire =
                            response_body(&format!("{parts}{terminal}={}", prefix.len()), &bytes);
                        let mut peer = Peer::new(wire);
                        peer.fragment = fragment;
                        let mut head = [0; 1024];
                        let mut line = [0; 128];
                        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                        tx.start(method_request(method, None)).await.unwrap();
                        if method != Method::Options {
                            tx.finish_body().await.unwrap();
                        }
                        let result = tx.read_response().await;
                        if !terminals.contains(&terminal) {
                            assert!(
                                matches!(result, Err(Error::Protocol(_))),
                                "accepted {method:?}, head={head_kind}, {terminal}"
                            );
                            assert!(tx.response().is_none());
                            assert!(matches!(
                                tx.read_body(&mut [0; 2]).await,
                                Err(Error::InvalidState)
                            ));
                            continue;
                        }
                        result.unwrap();
                        let mut decoded = Vec::new();
                        let mut out = [0; 2];
                        loop {
                            let n = tx.read_body(&mut out).await.unwrap();
                            if n == 0 {
                                break;
                            }
                            decoded.extend_from_slice(&out[..n]);
                        }
                        assert_eq!(
                            decoded,
                            if terminal == "null-body" {
                                b"".as_slice()
                            } else {
                                b"abc".as_slice()
                            }
                        );
                        assert_eq!(tx.response().unwrap().status_code(), 200);
                        assert_eq!(tx.response().unwrap().header("ISTag"), Some("\"v1\""));
                    }
                }
            }
        }
    });
}

#[test]
fn respmod_request_preserves_both_http_heads() {
    run(async {
        let req = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut peer = Peer::new(NO_CONTENT);
        let mut head = [0; 1024];
        let mut line = [0; 128];
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(RequestHead {
            http_request: req,
            ..request(None)
        })
        .await
        .unwrap();
        tx.write_body(b"abc").await.unwrap();
        tx.finish_body().await.unwrap();
        tx.read_response().await.unwrap();
        tx.discard_body(&mut [0; 2]).await.unwrap();
        let expected = format!(
            "Encapsulated: req-hdr=0, res-hdr={}, res-body={}\r\n\r\n",
            req.len(),
            req.len() + HTTP.len()
        );
        let wire = String::from_utf8(peer.output).unwrap();
        assert!(wire.contains(&expected));
        assert!(wire.ends_with("GET / HTTP/1.1\r\nHost: example.test\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n"));
    });
}

#[test]
fn preview_preserves_method_for_early_and_continued_finals() {
    run(async {
        for (method, terminal) in [
            (Method::ReqMod, "req-body"),
            (Method::ReqMod, "res-body"),
            (Method::RespMod, "res-body"),
        ] {
            for continued in [false, true] {
                for fragment in [1, usize::MAX] {
                    let mut wire = Vec::new();
                    if continued {
                        wire.extend_from_slice(
                            b"ICAP/1.0 100 Continue\r\nEncapsulated: null-body=0\r\n\r\n",
                        );
                    }
                    wire.extend_from_slice(&response_body(
                        &format!("{terminal}=0"),
                        b"3\r\nabc\r\n0\r\n\r\n",
                    ));
                    let mut peer = Peer::new(wire);
                    peer.fragment = fragment;
                    let mut head = [0; 1024];
                    let mut line = [0; 128];
                    let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                    tx.start(method_request(method, Some(0))).await.unwrap();
                    let decision = tx.finish_preview(false).await.unwrap();
                    if continued {
                        assert_eq!(decision, PreviewOutcome::Continue);
                        tx.write_body(b"original").await.unwrap();
                        tx.finish_body().await.unwrap();
                        tx.read_response().await.unwrap();
                    } else {
                        assert_eq!(decision, PreviewOutcome::Final);
                    }
                    let mut decoded = Vec::new();
                    let mut out = [0; 2];
                    loop {
                        let n = tx.read_body(&mut out).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        decoded.extend_from_slice(&out[..n]);
                    }
                    assert_eq!(decoded, b"abc");
                    assert_eq!(tx.response().unwrap().status_code(), 200);
                }
            }
        }
    });
}

#[test]
fn control_responses_reject_all_declared_entity_types() {
    run(async {
        for status in [100, 204] {
            for enc in [
                "req-body=0",
                "res-body=0",
                "opt-body=0",
                "req-hdr=0, null-body=38",
                "res-hdr=0, null-body=38",
            ] {
                for method in [Method::ReqMod, Method::RespMod] {
                    let wire = format!(
                        "ICAP/1.0 {status} Control\r\nISTag: v1\r\nEncapsulated: {enc}\r\n\r\n"
                    );
                    let mut peer = Peer::new(wire);
                    let mut head = [0; 1024];
                    let mut line = [0; 128];
                    let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                    tx.start(method_request(method, Some(0))).await.unwrap();
                    assert!(matches!(
                        tx.finish_preview(false).await,
                        Err(Error::Protocol("body on continue or no-content"))
                    ));
                    assert!(tx.response().is_none());
                }
            }
        }
    });
}

#[test]
fn exact_request_wire_and_incremental_preview() {
    run(async {
        for fragment in [1, 2, 7, usize::MAX] {
            let mut wire = b"ICAP/1.0 100 Continue\r\n\r\n".to_vec();
            wire.extend_from_slice(NO_CONTENT);
            let mut peer = Peer::new(wire);
            peer.fragment = fragment;
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(Some(2))).await.unwrap();
            tx.write_body(b"a").await.unwrap();
            tx.write_body(b"b").await.unwrap();
            assert_eq!(
                tx.finish_preview(false).await.unwrap(),
                PreviewOutcome::Continue
            );
            assert!(tx.response().is_none());
            tx.write_body(b"c").await.unwrap();
            tx.finish_body().await.unwrap();
            tx.read_response().await.unwrap();
            tx.discard_body(&mut [0; 5]).await.unwrap();
            assert_eq!(tx.response().unwrap().status_code(), 204);
            assert_eq!(tx.response().unwrap().header("istag"), Some("\"v1\""));
            let expected = format!(
                "RESPMOD icap://example.test:1344/process?mode=scan ICAP/1.0\r\nHost: example.test:1344\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAllow: 204\r\nPreview: 2\r\nEncapsulated: res-hdr=0, res-body={}\r\n\r\n",
                HTTP.len()
            );
            let mut expected = expected.into_bytes();
            expected.extend_from_slice(HTTP);
            expected.extend_from_slice(b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n1\r\nc\r\n0\r\n\r\n");
            assert_eq!(peer.output, expected);
        }
    });
}

#[test]
fn options_and_reqmod_offsets() {
    run(async {
        let mut peer = Peer::new(NO_CONTENT);
        let mut head = [0; 1024];
        let mut line = [0; 128];
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(options()).await.unwrap();
        tx.read_response().await.unwrap();
        tx.discard_body(&mut [0; 1]).await.unwrap();
        assert_eq!(peer.output, b"OPTIONS icap://example.test:1344/process?mode=scan ICAP/1.0\r\nHost: example.test:1344\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAllow: 204\r\nEncapsulated: null-body=0\r\n\r\n");

        let mut peer = Peer::new(NO_CONTENT);
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(RequestHead {
            method: Method::ReqMod,
            http_request: b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            http_response: b"",
            ..request(None)
        })
        .await
        .unwrap();
        tx.write_body(b"abc").await.unwrap();
        tx.finish_body().await.unwrap();
        tx.read_response().await.unwrap();
        tx.discard_body(&mut [0; 3]).await.unwrap();
        assert!(
            String::from_utf8(peer.output)
                .unwrap()
                .contains("req-hdr=0, req-body=38\r\n")
        );
    });
}

#[test]
fn zero_preview_early_final_and_ieof() {
    run(async {
        for (size, bytes) in [
            (0, b"".as_slice()),
            (3, b"abc".as_slice()),
            (10, b"abc".as_slice()),
        ] {
            let mut peer = Peer::new(NO_CONTENT);
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(Some(size))).await.unwrap();
            tx.write_body(bytes).await.unwrap();
            assert_eq!(
                tx.finish_preview(true).await.unwrap(),
                PreviewOutcome::Final
            );
            assert!(matches!(
                tx.write_body(b"more").await,
                Err(Error::InvalidState)
            ));
            tx.discard_body(&mut [0; 4]).await.unwrap();
            assert!(peer.output.ends_with(b"0; ieof\r\n\r\n"));
        }
        let mut peer = Peer::new(NO_CONTENT);
        let mut head = [0; 1024];
        let mut line = [0; 128];
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(request(Some(0))).await.unwrap();
        assert_eq!(
            tx.finish_preview(false).await.unwrap(),
            PreviewOutcome::Final
        );
        tx.discard_body(&mut [0; 1]).await.unwrap();
        assert!(peer.output.ends_with(b"0\r\n\r\n"));
    });
}

fn response_body(enc: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "ICAP/1.0 200 OK\r\nISTag: \"v1\"\r\nX-Result: present\r\nEncapsulated: {enc}\r\n\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(body);
    wire
}

#[test]
fn streamed_embedded_heads_chunks_extensions_and_trailers() {
    run(async {
        let res = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n";
        let mut body = res.to_vec();
        body.extend_from_slice(b"2; vendor=ok\r\nab\r\n1\r\nc\r\n0\r\nX-Trailer: ok\r\n\r\n");
        for fragment in [1, 3, 65536] {
            let wire = response_body(&format!("res-hdr=0, res-body={}", res.len()), &body);
            let mut peer = Peer::new(wire);
            peer.fragment = fragment;
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(None)).await.unwrap();
            tx.finish_body().await.unwrap();
            tx.read_response().await.unwrap();
            let mut decoded = Vec::new();
            let mut out = [0; 1];
            loop {
                let n = tx.read_body(&mut out).await.unwrap();
                if n == 0 {
                    break;
                }
                decoded.extend_from_slice(&out[..n]);
            }
            assert_eq!(decoded, b"abc");
            assert_eq!(tx.response().unwrap().header("X-Result"), Some("present"));
            assert_eq!(tx.read_body(&mut out).await.unwrap(), 0);
        }
    });
}

#[test]
fn malformed_heads_and_encapsulation_fail_closed() {
    run(async {
        let fixtures: &[&[u8]] = &[
            b"ICAP/1.0 200 OK\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 204 OK\r\nISTag: v1\r\nISTag: v2\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 204 OK\r\nISTag: v1\r\nEncapsulated: null-body=0\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: \"bad\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nBad Header: value\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nnot-a-header\r\nEncapsulated: null-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-body=1\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-hdr=0, res-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-hdr=0, req-hdr=10, res-body=20\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-hdr=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-body=0, null-body=0\r\n\r\n",
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: bogus=0\r\n\r\n",
            b"ICAP/1.0 204 OK\r\nISTag: v1\r\nEncapsulated: res-body=0\r\n\r\n",
            b"ICAP/1.0 100 Continue\r\n\r\n",
            b"ICAP/2.0 204 No Content\r\n\r\n",
            b"ICAP/1.0 200 OK\r\n",
        ];
        let errors = [
            "missing ISTag",
            "duplicate protocol header",
            "duplicate protocol header",
            "ISTag quotes",
            "header syntax",
            "missing header colon",
            "first encapsulated offset",
            "encapsulated offsets not increasing",
            "encapsulated header order",
            "missing encapsulated body marker",
            "part after encapsulated body",
            "unknown encapsulated part",
            "body on continue or no-content",
            "unexpected informational response",
            "ICAP version",
            "EOF in ICAP head",
        ];
        assert_eq!(fixtures.len(), errors.len());
        for (&wire, expected) in fixtures.iter().zip(errors) {
            let mut peer = Peer::new(wire);
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(None)).await.unwrap();
            tx.finish_body().await.unwrap();
            let result = tx.read_response().await;
            assert!(
                matches!(result, Err(Error::Protocol(message)) if message == expected),
                "expected {expected}, got {result:?} for {wire:?}"
            );
            assert!(tx.response().is_none());
            assert!(matches!(tx.read_response().await, Err(Error::InvalidState)));
        }
    });
}

#[test]
fn malformed_truncated_and_oversized_bodies_fail_closed() {
    run(async {
        let fixtures: &[&[u8]] = &[
            b"xyz\r\n",
            b"-1\r\n",
            b"+1\r\na\r\n0\r\n\r\n",
            b"10000000000000000\r\n",
            b"3\r\nab",
            b"3\r\nabc!\r\n0\r\n\r\n",
            b"0\r\nX-Trailer: unfinished",
            b"0; use-original-body=0\r\n\r\n",
            b"0; ieof\r\n\r\n",
            b"0\r\nISTag: changed\r\n\r\n",
            b"0\r\nmissing-colon\r\n\r\n",
            b"0\r\n\r\nextra",
        ];
        for &body in fixtures {
            for fragment in [1, usize::MAX] {
                if body.ends_with(b"extra") && fragment == 1 {
                    continue;
                }
                let mut peer = Peer::new(response_body("res-body=0", body));
                peer.fragment = fragment;
                let mut head = [0; 1024];
                let mut line = [0; 128];
                let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                tx.start(request(None)).await.unwrap();
                tx.finish_body().await.unwrap();
                tx.read_response().await.unwrap();
                assert!(
                    tx.discard_body(&mut [0; 7]).await.is_err(),
                    "accepted {body:?}"
                );
                assert!(tx.response().is_none());
            }
        }
        for (enc, body) in [
            (
                "res-hdr=0, res-body=20",
                b"HTTP/1.1 200 OK\r\n\r\n0\r\n\r\n".as_slice(),
            ),
            (
                "res-hdr=0, res-body=17",
                b"HTTP/1.1 200 OK\r\n\r\n0\r\n\r\n".as_slice(),
            ),
            ("res-hdr=0, res-body=4", b"oops0\r\n\r\n".as_slice()),
        ] {
            let mut peer = Peer::new(response_body(enc, body));
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(None)).await.unwrap();
            tx.finish_body().await.unwrap();
            tx.read_response().await.unwrap();
            assert!(tx.discard_body(&mut [0; 7]).await.is_err());
        }
    });
}

#[test]
fn workspace_limits_and_input_validation() {
    run(async {
        let mut peer = Peer::new(NO_CONTENT);
        let mut head = [0; 16];
        let mut line = [0; 32];
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        assert!(matches!(tx.start(options()).await, Err(Error::Limit(_))));
        assert!(peer.output.is_empty());

        let mut head = [0; 1024];
        for bad in [
            RequestHead {
                host: "host\r\nInjected: yes",
                ..options()
            },
            RequestHead {
                uri: "icap://example.test/a b",
                ..options()
            },
            RequestHead {
                headers: &[("Preview", "0")],
                ..options()
            },
            RequestHead {
                headers: &[("X", "good\r\nInjected: yes")],
                ..options()
            },
        ] {
            let mut peer = Peer::new(NO_CONTENT);
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            assert!(tx.start(bad).await.is_err());
            assert!(peer.output.is_empty());
        }
        let mut wire = b"ICAP/1.0 200 OK\r\nX-Large: ".to_vec();
        wire.extend_from_slice(&[b'x'; 1024]);
        let mut peer = Peer::new(wire);
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(options()).await.unwrap();
        assert!(matches!(tx.read_response().await, Err(Error::Limit(_))));

        for body in [
            format!("1;{}\r\na\r\n0\r\n\r\n", "x".repeat(32)),
            format!("0\r\n{}\r\n", "X: abcdefghijkl\r\n".repeat(3)),
        ] {
            let mut peer = Peer::new(response_body("res-body=0", body.as_bytes()));
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(None)).await.unwrap();
            tx.finish_body().await.unwrap();
            tx.read_response().await.unwrap();
            assert!(matches!(
                tx.discard_body(&mut [0; 8]).await,
                Err(Error::Limit(_))
            ));
        }
        let mut peer = Peer::new(response_body("res-hdr=0, res-body=999999", b""));
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(request(None)).await.unwrap();
        tx.finish_body().await.unwrap();
        assert!(matches!(tx.read_response().await, Err(Error::Limit(_))));
    });
}

#[test]
fn preview_counts_and_unexpected_continue() {
    run(async {
        for (count, eof, data) in [
            (1, false, b"ab".as_slice()),
            (2, false, b"a".as_slice()),
            (2, true, b"a".as_slice()),
        ] {
            let mut peer = Peer::new(b"ICAP/1.0 100 Continue\r\n\r\n".as_slice());
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(Some(count))).await.unwrap();
            let result = tx.write_body(data).await;
            if result.is_ok() {
                assert!(tx.finish_preview(eof).await.is_err());
            }
            assert!(tx.response().is_none());
            assert!(matches!(
                tx.write_body(b"x").await,
                Err(Error::InvalidState)
            ));
        }
    });
}

struct Paused;
impl Transport for Paused {
    async fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }
    async fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        std::future::pending().await
    }
    async fn flush(&mut self) -> io::Result<()> {
        std::future::pending().await
    }
}

#[test]
fn cancellation_poisoning_and_send_futures() {
    fn assert_send<T: Send>(_: &T) {}
    let mut peer = Paused;
    let mut head = [0; 1024];
    let mut line = [0; 128];
    let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
    {
        let mut future = pin!(tx.start(options()));
        assert_send(&future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(matches!(run(tx.start(options())), Err(Error::InvalidState)));
    assert!(tx.response().is_none());
}

/// A synthetic peer whose resident storage is independent of entity size. It
/// emits one large chunk and validates every uploaded byte without storing it.
struct LargePeer {
    phase: usize,
    offset: usize,
    size: usize,
    uploaded: usize,
}

const LARGE_HEAD: &[u8] =
    b"ICAP/1.0 200 OK\r\nISTag: v1\r\nEncapsulated: res-body=0\r\n\r\n4000000\r\n";

impl Transport for LargePeer {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.phase == 0 {
            let n = out.len().min(LARGE_HEAD.len() - self.offset);
            out[..n].copy_from_slice(&LARGE_HEAD[self.offset..self.offset + n]);
            self.offset += n;
            if self.offset == LARGE_HEAD.len() {
                self.phase = 1;
                self.offset = 0;
            }
            Ok(n)
        } else if self.phase == 1 {
            let n = out.len().min(self.size - self.offset);
            out[..n].fill(b'z');
            self.offset += n;
            if self.offset == self.size {
                self.phase = 2;
                self.offset = 0;
            }
            Ok(n)
        } else {
            let suffix = b"\r\n0\r\n\r\n";
            let n = out.len().min(suffix.len() - self.offset);
            out[..n].copy_from_slice(&suffix[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        }
    }
    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.uploaded += bytes.len();
        Ok(bytes.len())
    }
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn large_preview_and_response_use_fixed_workspaces() {
    run(async {
        let size = 64 * 1024 * 1024;
        let mut peer = LargePeer {
            phase: 0,
            offset: 0,
            size,
            uploaded: 0,
        };
        let mut head = [0; 1024];
        let mut line = [0; 128];
        let chunk = [b'a'; 4096];
        let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
        tx.start(request(Some(size as u64))).await.unwrap();
        for _ in 0..size / chunk.len() {
            tx.write_body(&chunk).await.unwrap();
        }
        assert_eq!(
            tx.finish_preview(true).await.unwrap(),
            PreviewOutcome::Final
        );
        let mut scratch = [0; 4096];
        let mut decoded = 0;
        loop {
            let n = tx.read_body(&mut scratch).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(scratch[..n].iter().all(|&b| b == b'z'));
            decoded += n;
        }
        assert_eq!(decoded, size);
        assert_eq!(tx.response().unwrap().status_code(), 200);
        assert!(peer.uploaded > size);
    });
}

#[test]
fn explicitly_enabled_folded_extension_headers_remain_borrowed() {
    const WIRE: &[u8] = b"ICAP/1.0 200 OK\r\nX-Violations-Found: 1\r\n\t-\r\n\tEicar-Test-Signature\r\n\t0\r\n\t0\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\nISTag: \"v1\"\r\nEncapsulated: null-body=0\r\n\r\n";
    run(async {
        for allow in [false, true] {
            for fragment in [1, usize::MAX] {
                let mut peer = Peer::new(WIRE);
                peer.fragment = fragment;
                let mut head = [0; 1024];
                let mut line = [0; 128];
                let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
                tx.allow_obs_fold(allow).unwrap();
                tx.start(options()).await.unwrap();
                assert!(matches!(tx.allow_obs_fold(true), Err(Error::InvalidState)));
                let result = tx.read_response().await;
                if !allow {
                    assert!(result.is_err());
                    continue;
                }
                result.unwrap();
                tx.discard_body(&mut [0; 1]).await.unwrap();
                let head = tx.response().unwrap();
                assert_eq!(
                    head.header("X-Violations-Found"),
                    Some("1\r\n\t-\r\n\tEicar-Test-Signature\r\n\t0\r\n\t0")
                );
                assert_eq!(
                    head.header("X-Infection-Found"),
                    Some("Type=0; Resolution=2; Threat=Eicar-Test-Signature;")
                );
                assert_eq!(head.header("ISTag"), Some("\"v1\""));
                assert_eq!(head.headers().count(), 4);
            }
        }
        for headers in [
            "\torphan\r\nISTag: v1\r\nEncapsulated: null-body=0\r\n",
            "ISTag: v1\r\n\tfolded\r\nEncapsulated: null-body=0\r\n",
            "ISTag: v1\r\nEncapsulated: null-body=\r\n\t0\r\n",
            "ISTag: v1\r\nPreview: 1\r\n\t0\r\nEncapsulated: null-body=0\r\n",
            "ISTag: v1\r\nPreview: 1\r\nPreview: 2\r\nEncapsulated: null-body=0\r\n",
            "ISTag: v1\r\nContent-Length: 1\r\n\t0\r\nEncapsulated: null-body=0\r\n",
            "ISTag: v1\r\nX: ok\r\n\tbad\nvalue\r\nEncapsulated: null-body=0\r\n",
        ] {
            let mut peer = Peer::new(format!("ICAP/1.0 200 OK\r\n{headers}\r\n"));
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.allow_obs_fold(true).unwrap();
            tx.start(options()).await.unwrap();
            assert!(tx.read_response().await.is_err(), "accepted {headers:?}");
        }
    });
}

#[test]
fn bare_204_after_continue_is_bodyless_compatibility() {
    run(async {
        for fragment in [1, 7, usize::MAX] {
            let mut wire = b"ICAP/1.0 100 Continue\r\n\r\n".to_vec();
            wire.extend_from_slice(BARE_NO_CONTENT);
            let mut peer = Peer::new(wire);
            peer.fragment = fragment;
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(Some(41))).await.unwrap();
            tx.write_body(&[b'a'; 41]).await.unwrap();
            assert_eq!(
                tx.finish_preview(false).await.unwrap(),
                PreviewOutcome::Continue
            );
            tx.finish_body().await.unwrap();
            tx.read_response().await.unwrap();
            tx.discard_body(&mut [0; 7]).await.unwrap();
            let response = tx.response().unwrap();
            assert_eq!(response.status_code(), 204);
            assert_eq!(response.header("Encapsulated"), None);
            assert_eq!(response.header("ISTag"), Some("\"example-signature\""));
            assert_eq!(response.header("Connection"), Some("close"));
        }
    });
}

#[test]
fn bare_204_does_not_relax_other_response_invariants() {
    run(async {
        let mut extra_body = BARE_NO_CONTENT.to_vec();
        extra_body.extend_from_slice(b"0\r\n\r\n");
        let mut extra_byte = BARE_NO_CONTENT.to_vec();
        extra_byte.push(b'x');
        for wire in [
            extra_body,
            extra_byte,
            b"ICAP/1.0 204 Unmodified\r\nISTag: v1\r\nEncapsulated: res-body=0\r\n\r\n0\r\n\r\n"
                .to_vec(),
            b"ICAP/1.0 204 Unmodified\r\nConnection: close\r\n\r\n".to_vec(),
            b"ICAP/1.0 200 OK\r\nISTag: v1\r\n\r\n".to_vec(),
        ] {
            let mut peer = Peer::new(wire);
            let mut head = [0; 1024];
            let mut line = [0; 128];
            let mut tx = Transaction::new(&mut peer, &mut head, &mut line).unwrap();
            tx.start(request(None)).await.unwrap();
            tx.finish_body().await.unwrap();
            if tx.read_response().await.is_ok() {
                assert!(tx.discard_body(&mut [0; 7]).await.is_err());
            }
            assert!(tx.response().is_none());
        }
    });
}
