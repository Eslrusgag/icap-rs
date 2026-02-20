# icap-rs — ICAP protocol for Rust

A Rust implementation of the **ICAP** protocol ([RFC 3507]) providing a client API and a server.

[RFC 3507]: https://www.rfc-editor.org/rfc/rfc3507

---

## Status

**Work in progress.**

- **Client**: functional — supports `OPTIONS`, `REQMOD`, `RESPMOD`, Preview (including `ieof`), embedded HTTP/1.x
  messages, streaming bodies, and optional connection reuse.
- **Server**: per-service routing, automatic `OPTIONS` responses (with optional **dynamic ISTag**),
  duplicate-route detection, safe reading of chunked bodies before invoking handlers, and an RFC-friendly **200 echo**
  fallback when `Allow: 204` is absent and `Preview` is not used.

---

## Features

- Client with builder (`Client::builder()`).
- ICAP requests: `OPTIONS`, `REQMOD`, `RESPMOD`.
- Embedded HTTP request/response serialization on the ICAP wire.
- **Preview** negotiation (incl. `Preview: 0` and `ieof` fast path).
- Chunked uploads, streaming large bodies after `100 Continue`.
- Streaming response body directly into an `AsyncWrite` sink (`...into_writer`) to avoid buffering.
- Keep-Alive: reuse a single idle connection.
- **ICAPS (TLS)** with `rustls` (ring) — see
- **GitHub / crates.io**: [docs/tls.md](docs/tls.md)

---

## Client

Builder-based configuration (host/port, keep-alive, default headers, timeouts).  
Generate exact wire bytes for debugging without sending.

### Quick start — `OPTIONS`

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icap://127.0.0.1:1344")?
        .keep_alive(true)
        .build();

    let req = Request::options("respmod");
    let resp = client.send(&req).await?;
    println!("ICAP: {} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### Streaming Request + Streaming Response (no buffered body)

```rust,no_run
use http::{Request as HttpRequest, Version};
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icap://127.0.0.1:1344")?
        .build();

    // Head-only embedded HTTP request (no Vec<u8> body attached here)
    let http_head = HttpRequest::builder()
        .method("POST")
        .uri("/upload")
        .version(Version::HTTP_11)
        .header("Host", "example.local")
        .header("Content-Length", "0")
        .body(())
        .unwrap();

    let req = Request::reqmod("scan")
        .preview(0)
        .preview_ieof()
        .with_http_request_head(http_head);

    // Stream request body from any AsyncRead source:
    let src = tokio::io::empty();
    // Stream response payload into any AsyncWrite sink:
    let mut dst = tokio::io::sink();

    let resp = client
        .send_streaming_reader_into_writer(&req, src, &mut dst)
        .await?;

    // response body is empty because payload was forwarded to `dst`
    assert!(resp.body.is_empty());
    Ok(())
}
```

---

## Server

- Async ICAP server built on Tokio.
- **Routing per service**, with **one handler** able to serve multiple methods.
- **Automatic `OPTIONS`** per service: `Methods` injected from registered routes; `Max-Connections` inherited from
  global limit.
- **Dynamic ISTag provider**: `ServiceOptions::with_istag_provider` lets you compute `ISTag` per request (incl.
  `OPTIONS`).
- **RFC guard**: if the request has **no** `Allow: 204` and **no** `Preview`, the server **must not** reply `204`;
  it will automatically send `200 OK` and **echo back** the embedded HTTP message (request for `REQMOD`, response for
  `RESPMOD`).
- **Duplicate route detection**: registering the same `(service, method)` twice panics with a clear message (axum-like
  DX).
- Reads encapsulated *chunked* bodies to completion before invoking handlers.

### ICAP status codes (re-exported from `http`)

ICAP reuses the **HTTP numeric status codes** (RFC 3507). This crate exposes them via a type alias:

```rust
pub type StatusCode = http::StatusCode;
```

Use `StatusCode::OK`, `StatusCode::NO_CONTENT`, etc. ICAP-specific rules (e.g., **`ISTag` is required on 2xx**,
`Encapsulated` constraints, and **204 must not carry a body**) are enforced by `icap-rs` during parsing and
serialization.

### Quick start — Server (plaintext)

A server exposing two services (`reqmod`, `respmod`) and replying `204 No Content`.

```rust,no_run
use icap_rs::{Server, Request, Response, StatusCode};
use icap_rs::server::options::ServiceOptions;

const ISTAG: &str = "example-1.0";

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    // Per-service OPTIONS config (Methods are injected by the router)
    let reqmod_opts = ServiceOptions::new()
        .with_service("Example REQMOD Service")
        .add_allow("204");

    let respmod_opts = ServiceOptions::new()
        .with_service("Example RESPMOD Service")
        .add_allow("204");

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // REQMOD → 204 (no changes). Encapsulated will be set automatically (null-body=0).
        .route_reqmod("reqmod", |_req: Request| async move {
            Ok(Response::no_content().try_set_istag(ISTAG)?)
        }, Some(reqmod_opts))
        // RESPMOD → 204 (also without body).
        .route_respmod("respmod", |_req: Request| async move {
            Ok(Response::no_content().try_set_istag(ISTAG)?)
        }, Some(respmod_opts))
        .build()
        .await?;

    server.run().await
}
```

### One handler for both methods

You can route by **strings** (case-insensitive) or enums. The same handler can handle both `REQMOD` and `RESPMOD`:

```rust,no_run
use icap_rs::{Server, Method, Request, Response, StatusCode};
use icap_rs::server::options::ServiceOptions;
use icap_rs::error::IcapResult;
use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};

const ISTAG: &str = "test-1.0";

fn make_http(body: &str) -> HttpResponse<Vec<u8>> {
    HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Length", body.len().to_string())
        .body(body.as_bytes().to_vec())
        .unwrap()
}

#[tokio::main]
async fn main() -> IcapResult<()> {
    let opts = ServiceOptions::new()
        .with_service("Test Service")
        .add_allow("204");

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // One handler handles both REQMOD and RESPMOD (strings are case-insensitive)
        .route("test", ["REQMOD", "respmod"], |req: Request| async move {
            let resp = match req.method {
                Method::ReqMod => {
                    // We don't change anything → 204
                    Response::no_content().try_set_istag(ISTAG)?
                }
                Method::RespMod => {
                    // Return 200 with embedded HTTP.
                    let http = make_http("hello from icap");
                    Response::new(StatusCode::OK, "OK")
                        .try_set_istag(ISTAG)?
                        .with_http_response(&http)?
                }
                Method::Options => unreachable!("OPTIONS is handled automatically"),
            };
            Ok(resp)
        }, Some(opts))
        .build()
        .await?;

    server.run().await
}
```
