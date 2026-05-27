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
    println!("ICAP {} {}", response.status_code(), response.status_text());
    Ok(())
}
```

To inspect the exact request bytes without sending them:

```rust
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
use icap_rs::{IcapResult, IncomingRequest, Response, Server, ServiceOptions};

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
            |_request: IncomingRequest| async move {
                Ok(Response::no_content_with_istag(ISTAG)?)
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

Preview is represented explicitly on both the client and server paths:
outbound [`Request`] values configure the wire behavior, [`Client::send`] and
[`Client::send_streaming_reader`] drive the client-side handshake, and server
routes receive [`IncomingRequest`] values that may expose [`Body::Preview`] to
preview-aware handlers.

Client requests can set `Preview: N` with [`Request::preview`] and optionally
send `ieof` for `Preview: 0` with [`Request::preview_ieof`]:

```rust
use http::{Request as HttpRequest, Version};
use icap_rs::{IcapResult, Request};

fn build_request() -> IcapResult<Request> {
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
If a [`ServerBuilder::route_reqmod`], [`ServerBuilder::route_respmod`], or
[`ServerBuilder::route`] handler returns [`IcapResult<PreviewDecision>`], it is
preview-aware: the server can call it after preview bytes arrive and before
sending `ICAP/1.0 100 Continue`.

```rust,no_run
use icap_rs::{IcapResult, IncomingRequest, PreviewDecision, Response, Server, ServiceOptions};

const ISTAG: &str = "preview-1.0";

#[tokio::main]
async fn main() -> IcapResult<()> {
    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "scan",
            |_request: IncomingRequest| async move {
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

Returning [`PreviewDecision::Continue`] resumes the RFC preview flow: the
server sends `100 Continue`, reads the remainder, and dispatches the full
request. Returning [`PreviewDecision::Respond`] sends the supplied final
[`Response`] immediately. Services advertise the preview window in generated
`OPTIONS` responses with [`ServiceOptions::with_preview`].

## Modifying an HTTP Request

For `REQMOD`, return `200 OK` with an embedded HTTP request when the service
changes the request. Return `204 No Content` only when no modification is
needed and the client allows that response.

This example adds an HTTP header to the encapsulated request and preserves the
original body:

```rust,no_run
use http::Request as HttpRequest;
use icap_rs::{Body, EmbeddedHttp, IcapResult, IncomingRequest, Response, Server, ServiceOptions};

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
            |request: IncomingRequest| async move {
                let Some(EmbeddedHttp::Req {
                    head,
                    body: Body::Full { reader },
                }) = request.into_embedded()
                else {
                    return Ok(Response::no_content_with_istag(ISTAG)?);
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
                    .map_err(|err| icap_rs::HandlerError::internal(
                        format!("build modified HTTP request: {err}")
                    ))?;

                Ok(Response::ok_with_istag(ISTAG)?
                    .with_http_request(&modified_http)?)
            },
            Some(options),
        )
        .build()
        .await?;

    server.run().await
}
```

## Streaming Bodies

The client can stream request bodies from an `AsyncRead` using
[`Client::send_streaming_reader`] and ICAP chunked framing. The final ICAP
response is parsed into [`Response`].

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
        .with_http_request_head(http_head)?;

    let source = tokio::io::empty();
    let response = client
        .send_streaming_reader(&request, source)
        .await?;

    println!("ICAP {} {}", response.status_code(), response.status_text());
    Ok(())
}
```

## Embedded HTTP

`REQMOD` can encapsulate an HTTP request, and `RESPMOD` can encapsulate an HTTP
response. The ICAP serializer computes `Encapsulated` offsets and writes the
embedded HTTP head unchunked. Only the encapsulated entity body is encoded with
ICAP chunked framing.

```rust
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

## ICAP Header Values

ICAP headers use `http::HeaderValue` validation. ASCII comma-separated values
such as `X-TEST: test1, test2, test3` are accepted and preserved as one header
value. The crate only applies list semantics for headers with explicit protocol
logic, such as `Allow`. Custom header list parsing belongs to caller code
because comma handling is header-specific.

```rust
use icap_rs::{IcapResult, Request, Response, StatusCode};

fn parse_comma_list(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn comma_separated_header_example() -> IcapResult<()> {
    let req: Request = Request::reqmod("scan")
        .try_icap_header("X-TEST", "test1, test2, test3")?;

    let raw_value = req
        .icap_headers()
        .get("X-TEST")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert_eq!(parse_comma_list(raw_value), vec!["test1", "test2", "test3"]);

    let resp = Response::new(StatusCode::NO_CONTENT, "No Content")
        .try_set_istag("example-1")?
        .try_add_header("X-TEST", "test1, test2, test3")?;

    let raw_value = resp
        .get_header("X-TEST")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert_eq!(parse_comma_list(raw_value), vec!["test1", "test2", "test3"]);

    Ok(())
}
```

## RFC 3507 Behavior

- `Host` is required on incoming ICAP requests.
- `Encapsulated` is required by the strict parser and validated for duplicate,
  non-monotonic, and method-incompatible forms.
- `OPTIONS`, `REQMOD`, and `RESPMOD` are supported.
- `Preview` supports `Preview: 0`, `Preview: N`, `ieof`, and `100 Continue`.
- Successful ICAP responses require a valid `ISTag`. Outgoing responses always
  serialize it as the RFC 3507 quoted-string form, so
  `Response::no_content_with_istag("QUJD+/8=")` writes
  `ISTag: "QUJD+/8="`. Incoming response parsing is intentionally more
  permissive and accepts unquoted token/base64-like values for compatibility
  with existing ICAP servers.
- Incoming client response parsing accepts legacy `204 No Content` responses
  without `Encapsulated` as equivalent to `Encapsulated: null-body=0`, matching
  c-icap behavior.
- Server `ServiceOptions` never invents a default `ISTag`. Every route must
  configure one explicitly with `with_static_istag(...)` or
  `with_istag_provider(...)`, because the tag is service policy metadata and
  should not be silently chosen by the framework.
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
    IncomingRequest, Method, PreviewDecision, Request, Response, Server, ServerBuilder,
    ServiceOptions, StatusCode, TransferBehavior,
};
```

| Type | Use it for |
| --- | --- |
| [`Client`], [`ClientBuilder`], [`ConnectionPolicy`] | Connecting to an ICAP service, configuring host/port or `icap://` / `icaps://` URI, keep-alive, timeouts, default headers, and streaming sends. |
| [`Request`], [`Method`] | Building outbound `OPTIONS`, `REQMOD`, and `RESPMOD` requests for client send/build APIs. |
| [`IncomingRequest`] | Inspecting server-side ICAP requests in route handlers. ICAP metadata is read-only; services may mutate or consume only the embedded HTTP message. |
| [`Response`], [`StatusCode`] | Building ICAP responses, parsing raw responses, validating `ISTag`, serializing RFC-compatible wire bytes, and attaching embedded HTTP messages. |
| [`Server`], [`ServerBuilder`] | Running a Tokio ICAP service with per-service routes, aliases, default service routing, connection limits, TLS/mTLS, and automatic `OPTIONS`. |
| [`ServiceOptions`], [`TransferBehavior`] | Describing per-service `OPTIONS` capabilities: `Methods`, `Service`, explicit `ISTag`, `Allow`, `Preview`, `Transfer-*`, `Options-TTL`, and optional `opt-body`. |
| [`Body`], [`EmbeddedHttp`] | Inspecting embedded HTTP request/response heads and bodies in server handlers. Regular handlers receive [`Body::Full`]; preview-aware handlers may receive [`Body::Preview`]. |
| [`PreviewDecision`] | Returning an early final response from a preview-aware route, or continuing the RFC preview flow. |
| [`Error`], [`IcapResult`] | Handling protocol, parsing, serialization, network, service, and handler errors without converting them into generic I/O errors. |

Submodules are still public for discoverability and namespacing:
`icap_rs::client`, `icap_rs::request`, `icap_rs::response`,
`icap_rs::server`, and `icap_rs::error`. Prefer the crate-root imports above
for normal application code.

Server route handlers receive [`IncomingRequest`], not the outbound [`Request`]
builder. This intentionally prevents services from rewriting the ICAP request
line, ICAP headers, preview state, or `Allow` flags after parsing. If a service
needs to adapt traffic, it should return a [`Response`] with an embedded HTTP
request/response, or use [`IncomingRequest::embedded_mut`] /
[`IncomingRequest::into_embedded`] to work with the encapsulated HTTP data.

### Common API Examples

Send an `OPTIONS` request with [`Client::send`] and [`Request::options`]:

```rust
use icap_rs::{Client, IcapResult, Request};

async fn options(client: &Client) -> IcapResult<()> {
    let response = client.send(&Request::options("respmod")).await?;
    println!("ICAP {}", response.status_code());
    Ok(())
}
```

Configure client-side network deadlines through [`ClientBuilder`]:

```rust
use std::time::Duration;
use icap_rs::Client;

let client = Client::builder()
    .with_uri("icap://icap.example:1344/respmod")?
    .timeout(Some(Duration::from_secs(60)))
    .connect_timeout(Some(Duration::from_secs(3)))
    .write_timeout(Some(Duration::from_secs(30)))
    .continue_timeout(Some(Duration::from_secs(10)))
    .try_build()?;
# Ok::<(), icap_rs::Error>(())
```

Build a buffered `REQMOD` request with [`Request::reqmod`] and
[`Request::with_http_request`]:

```rust
use http::Request as HttpRequest;
use icap_rs::{IcapResult, Request};

fn reqmod() -> IcapResult<Request> {
    let http = HttpRequest::builder()
        .method("GET")
        .uri("http://origin.example/")
        .header("Host", "origin.example")
        .body(Vec::new())
        .expect("valid HTTP request");

    Request::reqmod("scan").with_http_request(http)
}
```

Build a buffered `RESPMOD` request with [`Request::respmod`] and
[`Request::with_http_response`]:

```rust
use http::{Response as HttpResponse, StatusCode, Version};
use icap_rs::{IcapResult, Request};

fn respmod() -> IcapResult<Request> {
    let http = HttpResponse::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_11)
        .header("Content-Type", "text/plain")
        .body(b"hello".to_vec())
        .expect("valid HTTP response");

    Request::respmod("scan").with_http_response(http)
}
```

Use [`Request::try_new`] when the ICAP method comes from dynamic input:

```rust
use http::Request as HttpRequest;
use icap_rs::{IcapResult, Request};

fn dynamic_method(method: &str) -> IcapResult<Request> {
    let http = HttpRequest::builder()
        .method("GET")
        .uri("http://origin.example/")
        .header("Host", "origin.example")
        .body(Vec::new())
        .expect("valid HTTP request");

    Request::try_new(method, "scan")?.with_http_request(http)
}
```

Stream a large body by pairing [`Request::with_http_request_head`] with
[`Client::send_streaming_reader`]:

```rust
use http::Request as HttpRequest;
use icap_rs::{Client, IcapResult, Request};

async fn stream_reqmod(client: &Client) -> IcapResult<()> {
    let http_head = HttpRequest::builder()
        .method("POST")
        .uri("http://origin.example/upload")
        .header("Host", "origin.example")
        .body(())
        .expect("valid HTTP request head");

    let request = Request::reqmod("scan").with_http_request_head(http_head)?;
    let response = client
        .send_streaming_reader(&request, tokio::io::empty())
        .await?;

    println!("ICAP {}", response.status_code());
    Ok(())
}
```

Return no modification with [`Response::no_content_with_istag`], or return an
adapted HTTP message with [`Response::ok_with_istag`] and
[`Response::with_http_response`]:

```rust
use http::{Response as HttpResponse, StatusCode};
use icap_rs::{IcapResult, Response};

fn no_modification() -> IcapResult<Response> {
    Response::no_content_with_istag("policy-1")
}

fn adapted_response() -> IcapResult<Response> {
    let http = HttpResponse::builder()
        .status(StatusCode::OK)
        .body(b"adapted".to_vec())
        .expect("valid HTTP response");

    Response::ok_with_istag("policy-1")?.with_http_response(&http)
}
```

Run a service with [`Server::builder`], [`ServerBuilder::route_reqmod`], and
[`ServiceOptions`]:

```rust,no_run
use icap_rs::{IcapResult, IncomingRequest, Response, Server, ServiceOptions};

const ISTAG: &str = "policy-1";

async fn run() -> IcapResult<()> {
    let options = ServiceOptions::new()
        .with_static_istag(ISTAG)
        .allow_204()
        .with_preview(1024);

    let server = Server::builder()
        .bind("127.0.0.1:1344")
        .route_reqmod(
            "scan",
            |_request: IncomingRequest| async move {
                Ok(Response::no_content_with_istag(ISTAG)?)
            },
            Some(options),
        )
        .build()
        .await?;

    server.run().await
}
```

## TLS and ICAPS

Enable Rustls support with:

```toml
icap-rs = { version = "0.3.0", features = ["tls-rustls"] }
```

Then use `icaps://` URIs for clients, and `ServerBuilder::with_tls` plus a
[`ServerTlsConfig`](src/tls/server.rs) on the server side (use
`with_client_auth_pem` for in-memory PEM data or `with_client_auth_pem_file`
for file paths). On the client, customise TLS via
[`ClientTlsConfig`](src/tls/client.rs) and `ClientBuilder::with_tls`.
See the `icap_rs::tls` module documentation for the full guide.

## Examples

```bash
cargo run -p icap-rs --example server
cargo run -p icap-rs --example client
cargo run -p icap-rs --example streaming_client -- Cargo.toml
cargo run -p icap-rs --example preview_decision_server
cargo run -p icap-rs --example squid_interop_server
cargo run -p icap-rs --example tls_client --features tls-rustls
```
