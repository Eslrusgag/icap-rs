# icap-rs

A Rust implementation of the **ICAP** protocol ([RFC 3507]) providing a practical client API and a server.

[RFC 3507]: https://www.rfc-editor.org/rfc/rfc3507

## Status

**Work in progress.**

- **Client**: functional — supports `OPTIONS`, `REQMOD`, `RESPMOD`, Preview (including `ieof`), embedded HTTP/1.x
  messages, streaming bodies, and optional connection reuse.
- **Server**: experimental — per-service routing, automatic `OPTIONS` responses (with optional **dynamic ISTag**),
  duplicate-route detection, safe reading of chunked bodies before invoking handlers, and an RFC-friendly **200 echo**
  fallback when `Allow: 204` is absent and `Preview` is not used.

---

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
icap-rs = "0.0.2"
```

---

## Features

### Client

- Builder-based configuration (host/port, keep-alive, default headers, timeouts).
- ICAP requests: `OPTIONS`, `REQMOD`, `RESPMOD`.
- Embedded HTTP request/response (serialize on the ICAP wire).
- **Preview** negotiation, including `Preview: 0` with optional `ieof` hint (fast 204 path).
- Stream large bodies from disk after `100 Continue`.
- Generate exact wire bytes for debugging without sending.

### Server

- Minimal async ICAP server built on Tokio.
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

---

## Quick start — Client

### 1) Basic `OPTIONS`

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    // Transport (where to connect)
    let client = Client::builder()
        .from_uri("icap://127.0.0.1:1344")?
        .keep_alive(true)
        .build();

    // Semantics (which service to query)
    let req = Request::options("respmod"); // becomes icap://<host>/respmod

    let resp = client.send(&req).await?;
    println!("ICAP: {} {}", resp.status_code, resp.status_text);
    Ok(())
}
```

### 2) `REQMOD` with embedded HTTP and Preview

```rust,no_run
use http::Request as HttpRequest;
use icap_rs::{Client, Request, StatusCode};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder().from_uri("icap://127.0.0.1:1344")?.build();

    // Build the HTTP message to embed
    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/")
        .header("host", "127.0.0.1")
        .header("content-length", "5")
        .body(b"hello".to_vec())
        .unwrap();

    // ICAP request: REQMOD to service "test", advertise Allow: 204, and send Preview: 0 with ieof
    let icap_req = Request::reqmod("test")
        .allow_204()
        .preview(0)
        .preview_ieof()
        .with_http_request(http_req);

    let resp = client.send(&icap_req).await?;

    if resp.status_code == StatusCode::NoContent204 {
        println!("No modification needed (Allow 204)");
    } else {
        println!("{} {}", resp.status_code, resp.status_text);
        if !resp.body.is_empty() {
            println!("Body ({} bytes)", resp.body.len());
        }
    }
    Ok(())
}
```

---

## Quick start — Server

A minimal server exposing two services (`reqmod`, `respmod`) and replying `204 No Content`.

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
                    Response::new(StatusCode::Ok200, "OK")
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

---

## Dynamic ISTag (per-request)

If your service tag reflects a mutable policy (e.g., a filtering rule-set version), you can compute `ISTag`
**per request** (including `OPTIONS`):

```rust,no_run
use std::sync::{Arc, RwLock};
use icap_rs::server::options::ServiceOptions;
use icap_rs::request::Request;

let version = Arc::new(RwLock::new(String::from("respmod-1.0")));
let opts = ServiceOptions::new()
    .with_istag_provider({
        let version = version.clone();
        move |_: &Request| version.read().unwrap().clone()
    })
    .with_service("Response Modifier")
    .add_allow("204");
```

---

## 204 policy & automatic 200 echo

To align with RFC 3507 semantics:

- If the client **did not** advertise `Allow: 204` **and** **did not** use `Preview`, the server **must not** reply
  `204`.
- In such cases, the server automatically returns `200 OK` and **echoes the embedded HTTP** message back:
  - for `REQMOD` — echoes the HTTP request;
  - for `RESPMOD` — echoes the HTTP response.

When `Allow: 204` is present or `Preview` is used, your handler is free to return `204` where appropriate.

---

## Handlers and request parsing

Handlers receive a parsed `icap_rs::Request`, including ICAP headers and (if present) an embedded HTTP request/response
with its headers/body. The server reads and buffers the ICAP chunked body before invoking the handler, so your handler
logic can inspect `req.embedded` safely.

---

## API overview

Key types re-exported at the crate root:

- `Client` — high-level ICAP client with connection reuse.
- `Request` — build `OPTIONS`/`REQMOD`/`RESPMOD` (set Preview, `Allow: 204/206`, attach embedded HTTP).
- `Response`, `StatusCode` — build and serialize ICAP responses.
  - `Response::with_http_response(&http::Response<Vec<u8>>)` — attach embedded HTTP **response**.
  - `Response::with_http_request(&http::Request<Vec<u8>>)` — attach embedded HTTP **request**.
- `server::options::ServiceOptions` — construct per-service `OPTIONS` responses (router injects `Methods`).
  - `ServiceOptions::with_istag_provider(F: Fn(&Request) -> String + Send + Sync + 'static)` — **dynamic ISTag** per
    request.
- `error::{IcapError, IcapResult}` — error handling.

**Routing API highlights**

- `ServerBuilder::route(service, methods, handler, options)` — `methods` can be enum values or strings like
  `"REQMOD"`, `"RESPMOD"` (case-insensitive). `options` is `Option<ServiceOptions>`.
- `ServerBuilder::route_reqmod(service, handler, options)` / `route_respmod(service, handler, options)` — sugar.
- Duplicate `(service, method)` registrations **panic** with a clear message.

---

## Interop & notes

- ICAP and embedded HTTP headers are case-insensitive. When **serializing ICAP** headers, this crate uses canonical
  title-casing (e.g., `ISTag`, `Encapsulated`). Embedded HTTP header names follow the `http` crate’s representation.
- Connections are kept open by default on the server side; the client can reuse a single idle connection when configured
  to `keep_alive(true)`.
- For preview handling, servers typically respond with `100 Continue` before the client streams the remaining body.

---

## Roadmap

- TLS/ICAPS (likely via `rustls`).
- Richer server APIs (streaming to handler, trailers, backpressure, graceful shutdown).
- More complete `OPTIONS` helpers and better defaults.
- Connection pooling beyond a single keep-alive connection.
