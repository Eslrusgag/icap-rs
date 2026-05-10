# icap-rs

`icap-rs` is a Rust library for ICAP/1.0 clients and services, guided by
[RFC 3507](https://www.rfc-editor.org/rfc/rfc3507). It provides protocol
types, parsers, serializers, a Tokio-based client, and a Tokio-based server
API.

The crate focuses on explicit protocol behavior. Strict parsing is the default,
wire framing follows RFC 3507, and compatibility behavior is opt-in where it
exists.

## Feature Flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `tls-rustls` | No | Enables direct ICAPS (`icaps://`) client connections and TLS/mTLS server listeners through Rustls. |

Without `tls-rustls`, plaintext `icap://` clients and servers are available.

## Quick Start: Client

```rust,no_run
use icap_rs::{Client, IcapResult, Request};

#[tokio::main]
async fn main() -> IcapResult<()> {
    let client = Client::builder()
        .with_uri("icap://127.0.0.1:1344")?
        .keep_alive(true)
        .build();

    let response = client.send(&Request::options("respmod")).await?;
    println!("ICAP {} {}", response.status_code, response.status_text);
    Ok(())
}
```

To inspect the exact request bytes without sending them:

```rust,no_run
use icap_rs::{Client, IcapResult, Request};

fn main() -> IcapResult<()> {
    let client = Client::builder().host("icap.example").port(1344).build();
    let wire = client.get_request(&Request::options("respmod"))?;
    println!("{}", String::from_utf8_lossy(&wire));
    Ok(())
}
```

## Quick Start: Server

```rust,no_run
use icap_rs::{IcapResult, Request, Response, Server, ServiceOptions};

const ISTAG: &str = "example-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    let options = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Example RESPMOD Service")
        .allow_204()
        .with_preview(1024);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_respmod(
            "respmod",
            |_request: Request| async move {
                Response::no_content_with_istag(ISTAG)
            },
            Some(options),
        )
        .build()
        .await?;

    server.run().await
}
```

`OPTIONS` responses are generated automatically per service. The router injects
the advertised `Methods` value from registered routes and can inherit
`Max-Connections` from the server limit.

## Preview Flow

Preview is represented explicitly on both the client and server paths.

Client requests can set `Preview: N` and optionally send `ieof` for
`Preview: 0`:

```rust,no_run
use http::{Request as HttpRequest, Version};
use icap_rs::Request;

fn build_request() -> Request {
    let http_head = HttpRequest::builder()
        .method("POST")
        .uri("http://origin.example/upload")
        .version(Version::HTTP_11)
        .header("Host", "origin.example")
        .header("Content-Length", "0")
        .body(())
        .expect("valid HTTP request head");

    Request::reqmod("scan")
        .allow_204()
        .preview(0)
        .preview_ieof()
        .with_http_request_head(http_head)
}
```

Server handlers normally receive the request after the full body is available.
If a route handler returns `IcapResult<PreviewDecision>`, it is preview-aware:
the server can call it after preview bytes arrive and before sending
`ICAP/1.0 100 Continue`.

```rust,no_run
use icap_rs::{IcapResult, PreviewDecision, Request, Response, Server, ServiceOptions};

const ISTAG: &str = "preview-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "scan",
            |_request: Request| async move {
                Ok(PreviewDecision::Respond(
                    Response::no_content_with_istag(ISTAG)?,
                ))
            },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("Preview scanner")
                    .allow_204()
                    .with_preview(1024),
            ),
        )
        .build()
        .await?;

    server.run().await
}
```

Returning `PreviewDecision::Continue` resumes the RFC preview flow: the server
sends `100 Continue`, reads the remainder, and dispatches the full request.

## Modifying an HTTP Request

For `REQMOD`, return `200 OK` with an embedded HTTP request when the service
changes the request. Return `204 No Content` only when no modification is
needed and the client allows that response.

This example adds an HTTP header to the encapsulated request and preserves the
original body:

```rust,no_run
use http::Request as HttpRequest;
use icap_rs::{Body, EmbeddedHttp, IcapResult, Request, Response, Server, ServiceOptions};

const ISTAG: &str = "reqmod-edit-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    let options = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .with_service("Request modifier")
        .allow_204();

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "reqmod",
            |request: Request| async move {
                let Some(EmbeddedHttp::Req {
                    head,
                    body: Body::Full { reader },
                }) = request.embedded
                else {
                    return Response::no_content_with_istag(ISTAG);
                };

                let mut builder = HttpRequest::builder()
                    .method(head.method().clone())
                    .uri(head.uri().clone())
                    .version(head.version());

                if let Some(headers) = builder.headers_mut() {
                    headers.extend(head.headers().clone());
                    headers.insert(
                        "x-icap-processed-by",
                        http::HeaderValue::from_static("icap-rs"),
                    );
                }

                let modified_http = builder
                    .body(reader)
                    .map_err(|err| icap_rs::error::Error::body(
                        format!("build modified HTTP request: {err}")
                    ))?;

                Response::ok_with_istag(ISTAG)?
                    .with_http_request(&modified_http)
            },
            Some(options),
        )
        .build()
        .await?;

    server.run().await
}
```

## Streaming Bodies

The client can stream request bodies from an `AsyncRead` and write response
payload bytes directly into an `AsyncWrite` sink. This avoids buffering large
payloads in `Response::body`.

```rust,no_run
use http::{Request as HttpRequest, Version};
use icap_rs::{Client, IcapResult, Request};

#[tokio::main]
async fn main() -> IcapResult<()> {
    let client = Client::builder()
        .with_uri("icap://127.0.0.1:1344")?
        .build();

    let http_head = HttpRequest::builder()
        .method("POST")
        .uri("http://origin.example/upload")
        .version(Version::HTTP_11)
        .header("Host", "origin.example")
        .header("Content-Length", "0")
        .body(())
        .expect("valid HTTP request head");

    let request = Request::reqmod("scan")
        .preview(0)
        .with_http_request_head(http_head);

    let source = tokio::io::empty();
    let mut sink = tokio::io::sink();

    let response = client
        .send_streaming_reader_into_writer(&request, source, &mut sink)
        .await?;

    assert!(response.body.is_empty());
    Ok(())
}
```

## Embedded HTTP

`REQMOD` can encapsulate an HTTP request, and `RESPMOD` can encapsulate an HTTP
response. The ICAP serializer computes `Encapsulated` offsets and writes the
embedded HTTP head unchunked. Only the encapsulated entity body is encoded with
ICAP chunked framing.

```rust,no_run
use http::{Response as HttpResponse, StatusCode as HttpStatus, Version};
use icap_rs::{IcapResult, Response};

fn icap_response() -> IcapResult<Response> {
    let http = HttpResponse::builder()
        .status(HttpStatus::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/plain")
        .header("Content-Length", "5")
        .body(b"hello".to_vec())
        .expect("valid HTTP response");

    Response::ok_with_istag("example-1.0")?
        .with_http_response(&http)
}
```

## RFC 3507 Behavior

- `Host` is required on incoming ICAP requests.
- `Encapsulated` is required by the strict parser and validated for duplicate,
  non-monotonic, and method-incompatible forms.
- `OPTIONS`, `REQMOD`, and `RESPMOD` are supported.
- `Preview` supports `Preview: 0`, `Preview: N`, `ieof`, and `100 Continue`.
- Successful ICAP responses require a valid `ISTag`.
- `204 No Content` is serialized as `Encapsulated: null-body=0` and must not
  carry body bytes.
- Server handlers that return `204` are guarded: if the request has neither
  `Allow: 204` nor Preview, the server returns `200 OK` and echoes the embedded
  HTTP message instead.
- `Allow: 206` no-modification responses use the `use-original-body` marker.
- Keep-alive is supported without request pipelining.

For the detailed support matrix and known gaps, see
[`docs/rfc3507.md`](docs/rfc3507.md).

## Public API Map

Most applications can import the main API directly from the crate root:

```rust
use icap_rs::{
    Body, Client, ClientBuilder, ConnectionPolicy, EmbeddedHttp, Error, IcapResult,
    Method, PreviewDecision, Request, Response, Server, ServerBuilder,
    ServiceOptions, StatusCode, TransferBehavior,
};
```

| Type | Use it for |
| --- | --- |
| `Client`, `ClientBuilder`, `ConnectionPolicy` | Connecting to an ICAP service, configuring host/port or `icap://` / `icaps://` URI, keep-alive, timeouts, default headers, and streaming sends. |
| `Request`, `Method` | Building outbound `OPTIONS`, `REQMOD`, and `RESPMOD` requests, or inspecting requests received by server route handlers. |
| `Response`, `StatusCode` | Building ICAP responses, parsing raw responses, validating `ISTag`, serializing RFC-compatible wire bytes, and attaching embedded HTTP messages. |
| `Server`, `ServerBuilder` | Running a Tokio ICAP service with per-service routes, aliases, default service routing, connection limits, TLS/mTLS, and automatic `OPTIONS`. |
| `ServiceOptions`, `TransferBehavior` | Describing per-service `OPTIONS` capabilities: `Methods`, `Service`, `ISTag`, `Allow`, `Preview`, `Transfer-*`, `Options-TTL`, and optional `opt-body`. |
| `Body`, `EmbeddedHttp` | Inspecting embedded HTTP request/response heads and bodies in server handlers. Regular handlers receive `Body::Full`; preview-aware handlers may receive `Body::Preview`. |
| `PreviewDecision` | Returning an early final response from a preview-aware route, or continuing the RFC preview flow. |
| `Error`, `IcapResult` | Handling protocol, parsing, serialization, network, service, and handler errors without converting them into generic I/O errors. |

Submodules are still public for discoverability and namespacing:
`icap_rs::client`, `icap_rs::request`, `icap_rs::response`,
`icap_rs::server`, and `icap_rs::error`. Prefer the crate-root imports above
for normal application code.

### Common API Paths

| Goal | API path |
| --- | --- |
| Send `OPTIONS` | `Client::send(&Request::options("service"))` |
| Send buffered `REQMOD` | `Request::reqmod("service").with_http_request(http_request)` then `Client::send` |
| Send buffered `RESPMOD` | `Request::respmod("service").with_http_response(http_response)` then `Client::send` |
| Stream a large body | `with_http_request_head` / `with_http_response_head` plus `Client::send_streaming_reader` |
| Return no modification | `Response::no_content_with_istag("...")` |
| Return adapted HTTP | `Response::ok_with_istag("...")?.with_http_response(...)` |
| Run a service | `Server::builder().route_reqmod(...)` / `route_respmod(...)` / `route(...)` |
| Advertise capabilities | `ServiceOptions::new().with_static_istag(...).allow_204().with_preview(...)` |

## TLS and ICAPS

Enable Rustls support with:

```toml
icap-rs = { version = "0.2.0", features = ["tls-rustls"] }
```

Then use `icaps://` URIs for clients or `ServerBuilder::with_tls_from_pem_files`
and `ServerBuilder::with_mtls_from_pem_files` for listeners. See
[`docs/tls.md`](docs/tls.md).

## Examples

```bash
cargo run -p icap-rs --example server
cargo run -p icap-rs --example client
cargo run -p icap-rs --example preview_decision_server
cargo run -p icap-rs --example tls_client --features tls-rustls
```
