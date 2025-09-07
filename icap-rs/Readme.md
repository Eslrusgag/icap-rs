# icap-rs — ICAP protocol for Rust (client & mini server)

A Rust implementation of the **ICAP** protocol ([RFC&nbsp;3507]) providing a client API and a small server.

[RFC&nbsp;3507]: https://www.rfc-editor.org/rfc/rfc3507

---

## Status

**Work in progress.**

- **Client**: functional — supports `OPTIONS`, `REQMOD`, `RESPMOD`, Preview (including `ieof`), embedded HTTP/1.x
  messages, streaming bodies, and optional connection reuse.
- **Server**: experimental — per-service routing, automatic `OPTIONS` responses (with optional **dynamic ISTag**),
  duplicate-route detection, safe reading of chunked bodies before invoking handlers, and an RFC-friendly **200 echo**
  fallback when `Allow: 204` is absent and `Preview` is not used.

---

## Features

- Client with builder (`Client::builder()`).
- ICAP requests: `OPTIONS`, `REQMOD`, `RESPMOD`.
- Embedded HTTP request/response serialization on the ICAP wire.
- **Preview** negotiation (incl. `Preview: 0` and `ieof` fast path).
- Chunked uploads, streaming large bodies after `100 Continue`.
- Keep-Alive: reuse a single idle connection.
- **ICAPS (TLS)** with either `rustls` or `OpenSSL` backends.

---

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
icap-rs = "actual-version"
```

Or:

```bash
cargo add icap-rs
```

---

## Client

Builder-based configuration (host/port, keep-alive, default headers, timeouts).  
Generate exact wire bytes for debugging without sending.

### Quick start — `OPTIONS`

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
    println!("ICAP: {} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### `REQMOD` with embedded HTTP and Preview

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

    if resp.status_code == StatusCode::NO_CONTENT {
        println!("No modification needed (Allow 204)");
    } else {
        println!("{} {}", resp.status_code.as_str(), resp.status_text);
        if !resp.body.is_empty() {
            println!("Body ({} bytes)", resp.body.len());
        }
    }
    Ok(())
}
```

### Streaming from disk after `100 Continue`

```rust,no_run
use icap_rs::{Client, Request};
use http::{Request as HttpRequest, header, Version};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder().from_uri("icap://127.0.0.1:1344")?.build();

    // Tell the ICAP server we will have a body, but send Preview: 0
    let http_req = HttpRequest::builder()
        .method("POST")
        .uri("/upload")
        .version(Version::HTTP_11)
        .header(header::HOST, "app")
        .header(header::CONTENT_LENGTH, "10000000")
        .body(Vec::<u8>::new()) // empty now; we'll stream from a file
        .unwrap();

    let req = Request::reqmod("upload").preview(0).with_http_request(http_req);

    // After the server replies 100 Continue, the client streams the file
    let resp = client.send_streaming(&req, "/path/to/large.bin").await?;
    println!("{} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

---

## TLS (ICAPS)

The client supports **TLS (“ICAPS”)**. You can enable one of two TLS stacks:

- **rustls** (recommended):
  - Enable `tls-rustls` **and pick exactly one provider**:
    - `tls-rustls-ring` **or**
    - `tls-rustls-aws-lc`
- **OpenSSL**:
  - Enable `tls-openssl`

> If you enable both rustls providers or none, the crate fails to compile with a clear error.  
> When you use an `icaps://…` URI but build without any TLS feature, the client returns an error.

### Cargo features

```toml
# Choose ONE rustls provider:
[dependencies.icap-rs]
version = "actual-version"
features = ["tls-rustls", "tls-rustls-ring"]      # or: ["tls-rustls", "tls-rustls-aws-lc"]

# — OR — use OpenSSL instead:
# features = ["tls-openssl"]
```

### ICAPS quick start (system roots)

`icaps://` switches the client into TLS mode automatically. If you omit the port, the default for ICAPS is **11344**.

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .from_uri("icaps://icap.example")? // TLS on port 11344 by default
        .keep_alive(true)
        .build();

    let req = Request::options("respmod");
    let resp = client.send(&req).await?;
    println!("ICAP: {} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### rustls: trust a local CA (self-signed)

If your server uses a self-signed certificate, add its **CA** to the client trust store (PEM).  
This method is available only with the `tls-rustls` feature.

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .from_uri("icaps://localhost:2346")?
        .sni_hostname("localhost")                    // SNI to match cert
        .add_root_ca_pem_file("/var/tmp/test/ca.crt")? // trust our CA
        .keep_alive(true)
        .build();

    let resp = client.send(&Request::options("test")).await?;
    println!("{} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### SNI override

By default SNI is the ICAP host (or `host_override` if set). You can override it:

```rust,no_run
use icap_rs::Client;
# fn demo() -> Result<(), Box<dyn std::error::Error>> {
  let client = Client::builder()
          .from_uri("icaps://10.0.0.5:2346")?   // this returns Result, so `?` is fine
          .sni_hostname("icap.internal.example") // this returns the builder; no `?` here
          .build();
  # Ok(())
  # }
# demo().unwrap();
```

### OpenSSL backend (testing only: disable verify)

With the OpenSSL backend you can temporarily disable verification (e.g., quick local tests).  
**Do not** use this in production.

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .from_uri("icaps://localhost:2346")?
        .keep_alive(true)
        .danger_disable_cert_verify(true) // OpenSSL: disables verify; rustls: ignored
        .build();

    let resp = client.send(&Request::options("test")).await?;
    println!("{} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### Notes & limitations

- **rustls 0.23**: certificate verification **cannot be disabled** via public API.  
  The builder’s `danger_disable_cert_verify(true)` flag is **ignored** under rustls (kept only for API compatibility).
- **Client auth (mTLS)**: the client currently does **not** present a certificate (no client-auth).  
  If your server *requires* a client certificate, the handshake will fail.
- **Default ICAPS port**: if no port is specified for `icaps://host`, the client uses **11344**.  
  For `icap://host` (plaintext), the default is **1344**.

---

## Example CLI (optional)

This repository may include a demo binary, `rs-icap-client`, that exercises the client API.

```bash
# OPTIONS over TLS (rustls), trusting a local CA file and setting SNI
cargo run --bin rs-icap-client --   -u icaps://localhost:2346/test   --tls-backend rustls   --tls-ca /var/tmp/test/ca.crt   --sni localhost   -v -d 4
```

Common flags: `--method`, `--req`, `--resp`, `--xheader`, `--hx`, `--rhx`, `--preview-size`, `--ieof`, `--stream-io`,
`--print-request`, etc.

---

## Server

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

### ICAP status codes (re-exported from `http`)

ICAP reuses the **HTTP numeric status codes** (RFC 3507). This crate exposes them via a type alias:

```rust
pub type StatusCode = http::StatusCode;
```

Use `StatusCode::OK`, `StatusCode::NO_CONTENT`, etc. ICAP-specific rules (e.g., **`ISTag` is required on 2xx**,
`Encapsulated` constraints, and **204 must not carry a body**) are enforced by `icap-rs` during parsing and
serialization.

### Quick start — Server

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

### Dynamic ISTag (per-request)

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

### 204 policy & automatic 200 echo

To align with RFC 3507 semantics:

- If the client **did not** advertise `Allow: 204` **and** **did not** use `Preview`, the server **must not** reply
  `204`.
- In such cases, the server automatically returns `200 OK` and **echoes the embedded HTTP** message back:
  - for `REQMOD` — echoes the HTTP request;
  - for `RESPMOD` — echoes the HTTP response.

When `Allow: 204` is present or `Preview` is used, your handler is free to return `204` where appropriate.

---

## Interop & notes

- ICAP and embedded HTTP headers are case-insensitive. When **serializing ICAP** headers, this crate uses canonical
  title-casing (e.g., `ISTag`, `Encapsulated`). Embedded HTTP header names follow the `http` crate’s representation.
- **ICAP status line formatting:** you must format `ICAP/1.0 <code> <reason>` yourself; do not print `StatusCode`
  with `Display` to avoid getting `"200 OK"` as the code token.
- Connections are kept open by default on the server side; the client can reuse a single idle connection when configured
  to `keep_alive(true)`.
- For preview handling, servers typically respond with `100 Continue` before the client streams the remaining body.

---

## Testing locally (plain or TLS)

Quick ad‑hoc servers for development:

### Plain TCP with `socat`

```bash
socat -v TCP-LISTEN:1344,reuseaddr,fork   SYSTEM:'printf "ICAP/1.0 200 OK\r\nISTag: test\r\nEncapsulated: null-body=0\r\n\r\n"; sleep 1'
```

### TLS with `openssl s_server` (self-signed)

```bash
# Generate a local CA and server cert (example only!)
# ... or use your existing cert and key:
openssl req -x509 -newkey rsa:2048 -nodes -days 1   -keyout server.key -out server.crt -subj "/CN=localhost"

# Start a toy TLS server that writes a single OPTIONS response
openssl s_server -quiet -accept 2346 -cert server.crt -key server.key -nocache -www <<'EOF'
ICAP/1.0 200 OK
ISTag: test
Encapsulated: null-body=0

EOF
```

Then run the client (trusting your CA/cert as needed).

---

## Roadmap

- Richer server APIs (streaming to handler, trailers, backpressure, graceful shutdown).
- More complete `OPTIONS` helpers and better defaults.
- TLS client auth (mTLS).
- Connection pooling beyond a single keep-alive connection.

---

## License

Dual-license or project-specific license TBD. Replace this section with your actual license details.
