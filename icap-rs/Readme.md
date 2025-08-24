# icap-rs

A Rust implementation of the **ICAP** protocol ([RFC 3507]) providing a practical client API and a server.

[RFC 3507]: https://www.rfc-editor.org/rfc/rfc3507

## Status

**Work in progress.**

- **Client**: functional — supports `OPTIONS`, `REQMOD`, `RESPMOD`, Preview (including `ieof`), embedded HTTP/1.x
  messages, streaming bodies, and optional connection reuse.
- **Server**: experimental — per-service routing, automatic `OPTIONS` responses, duplicate-route detection,
  safe reading of chunked bodies before invoking handlers.

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
        .allow_204(true)
        .preview(0)
        .preview_ieof(true)
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
use icap_rs::options::OptionsConfig;

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // REQMOD → 204 (no changes)
        .route_reqmod("reqmod", |_req: Request| async move {
            Ok(Response::no_content().add_header("Content-Length", "0"))
        })
        // RESPMOD → 204 as well
        .route_respmod("respmod", |_req: Request| async move {
            Ok(Response::no_content().add_header("Content-Length", "0"))
        })
        // Per-service OPTIONS config (no need to list Methods — router injects them)
        .set_options(
            "reqmod",
            OptionsConfig::new("example-reqmod-1.0")
                .with_service("Example REQMOD Service")
                .with_options_ttl(600)
                .add_allow("204"),
        )
        .set_options(
            "respmod",
            OptionsConfig::new("example-respmod-1.0")
                .with_service("Example RESPMOD Service")
                .with_options_ttl(600)
                .add_allow("204"),
        )
        .build()
        .await?;

    server.run().await
}
```

### One handler for both methods

You can route by **strings** (case-insensitive) or enums. The same handler can handle both `REQMOD` and `RESPMOD`:

```rust,no_run
use icap_rs::{Server, Method, Request, Response, StatusCode};
use icap_rs::error::IcapResult;

#[tokio::main]
async fn main() -> IcapResult<()> {
    let server = Server::builder()
        .bind("127.0.0.1:1344")
        // Accept both REQMOD and RESPMOD using strings (case-insensitive)
        .route("spool", ["REQMOD", "respmod"], |req: Request| async move {
            match req.method {
                Method::ReqMod => {
                    // request logic
                }
                Method::RespMod => {
                    // response logic
                }
                Method::Options => unreachable!("OPTIONS is handled automatically"),
            }

            Ok(Response::new(StatusCode::Ok200, "OK")
                .add_header("Encapsulated", "null-body=0")
                .add_header("Content-Length", "0"))
        })
        .build()
        .await?;

    server.run().await
}
```

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
- `Response`, `ResponseBuilder`, `StatusCode` — build and serialize ICAP responses.
- `options::{OptionsConfig, IcapOptionsBuilder, IcapMethod, TransferBehavior}` — construct `OPTIONS`.
  - `OptionsConfig::new(istag)` **no longer** takes methods; the router injects `Methods` automatically.
  - `IcapOptionsBuilder::new(istag)` likewise doesn’t take methods.
- `error::{IcapError, IcapResult}` — error handling.

**Routing API highlights**

- `ServerBuilder::route(service, methods, handler)` — `methods` can be `IcapMethod` values **or strings** like
  `"REQMOD"`, `"RESPMOD"` (case-insensitive).
- `ServerBuilder::route_reqmod(...)` / `route_respmod(...)` — sugar for common cases.
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
