# Architecture

This document describes the internal structure of the `icap-rs` crate. Keep it
up-to-date whenever you add, remove, or materially change a module, public
type, or data-flow invariant.

---

## Workspace layout

```
icap-rs/               ← Core library
rs-icap-client/        ← CLI ICAP client (inspired by c-icap-client)
rs-icap-server/        ← CLI ICAP server placeholder
```

The two CLI crates are thin shells. All protocol logic lives in `icap-rs`.

---

## Module tree

```
src/
├── lib.rs               re-exports, public constants
├── error.rs             hierarchical error types
├── request.rs           Request<R,D>, Body<R>, EmbeddedHttp<R>, Method
├── response.rs          Response<D>, StatusCode (re-export)
├── net.rs               Conn enum (plain TCP | TLS stream)
├── protocol/            wire-level parsing and serialization
│   ├── chunked.rs       ICAP chunked framing (read/write/dechunk)
│   ├── encapsulated.rs  Encapsulated header parsing
│   ├── headers.rs       ICAP response head parser, serializer
│   ├── http_embed.rs    embedded HTTP request/response serialization
│   └── istag.rs         ISTag validation and quoting
├── client/
│   ├── builder.rs       ClientBuilder, ConnectionPolicy
│   ├── timeouts.rs      ClientTimeouts
│   └── client.rs        Client — send / streaming / get_request
├── server/
│   ├── builder.rs       ServerBuilder
│   ├── connection.rs    per-connection read-parse-route-respond loop
│   ├── router.rs        RequestHandler, RouteEntry, RouteOutput trait, resolve_service
│   ├── handler.rs       HandlerError, HandlerResult
│   ├── preview.rs       PreviewDecision
│   ├── options.rs       ServiceOptions, IstagSource, TransferBehavior
│   ├── no_modification.rs  build_206_use_original_body helper
│   ├── errors.rs        write_wire_*_response helpers
│   └── timeouts.rs      ServerTimeouts
└── tls/                 feature-gated: tls-rustls
    ├── client.rs        ClientTlsConfig → ClientTlsConnector
    ├── server.rs        ServerTlsConfig → TlsAcceptor
    ├── pem.rs           PEM loading helpers
    └── error.rs         TlsError
```

### Layering rules

```
error, protocol/           ← no internal dependencies
request, response, net     ← depend on error + protocol only
client/, server/           ← depend on all layers above
tls/                       ← depends on error only; orthogonal to client/server
```

Nothing in `protocol/` may import from `client/`, `server/`, or `tls/`.  
Nothing in `error.rs` may import from any other internal module.

---

## Key types

### Direction markers

Every `Request` and `Response` carries a phantom direction marker:

| Type alias | Marker | Used by |
|---|---|---|
| `OutboundRequest<R>` | `Outbound` | Client — builder shape, setters unlocked |
| `IncomingRequest<R>` | `Incoming` | Server — ICAP metadata read-only |
| `OutgoingResponse` | `Outgoing` | Server — builder shape, setters unlocked |
| `ParsedResponse` | `Parsed` | Client — read-only view of wire response |

This encoding makes it a compile-time error to call a server-only builder method
from client code, or to mutate ICAP request metadata inside a handler.

### Request

```
Request<R, D>
  method: Method                   REQMOD | RESPMOD | OPTIONS
  service: String                  last path segment of the ICAP URI
  icap_headers: HeaderMap
  embedded: Option<EmbeddedHttp<R>>
  preview_size: Option<usize>
  allow_204 / allow_206: bool
  preview_ieof: bool               true → send "0; ieof" chunk
```

`R` is the body carrier:
- `Vec<u8>` on the client side (buffered)
- `Box<dyn AsyncRead + Unpin + Send>` (`BodyRead`) on the server side (streaming)

### Body

```
Body<R>
  Empty
  Preview { bytes: Bytes, ieof: bool, remainder: Remainder<R> }
  Full    { reader: R }
```

Regular server handlers always receive `Body::Full` because the server resolves
the preview handshake before invoking them. Preview-aware handlers (return type
`HandlerResult<PreviewDecision>`) may see `Body::Preview`.

### EmbeddedHttp

```
EmbeddedHttp<R>
  Req  { head: HttpRequest<()>,  body: Body<R> }
  Resp { head: HttpResponse<()>, body: Body<R> }
```

The HTTP head is always fully parsed and available. The body follows the
`Body<R>` variants described above.

### Error

```
Error
  Io(io::Error)
  Timeout(TimeoutError)            which deadline expired (TimeoutKind)
  Protocol(ProtocolError)          wire parse/encode failures
  Config(ConfigError)              builder/registration mistakes
  Tls(TlsError)                    TLS-specific failures (feature-gated)
  Http(http::Error)
  External(BoxError)
```

`ProtocolError` carries the specific field name or token that was invalid.
`ConfigError` identifies the service or alias that was mis-configured.
`TimeoutKind` names the deadline: connect, write, idle keepalive, 100-Continue
wait, header read, body read, TLS handshake.

Classifier helpers on `Error`: `is_io()`, `is_timeout()`, `is_protocol()`,
`is_config()`, `is_early_close()`, `is_retryable()`.

---

## Data flows

### Client send

```
ClientBuilder::build() → Client

Client::send(req)
  1. acquire / create Conn (plain TCP or TLS via ClientTlsConnector)
  2. build_icap_request_bytes(req)
       → compute Encapsulated offsets
       → serialize embedded HTTP head (unchunked)
       → chunk preview bytes (if preview_size set)
  3. write bytes to Conn (with write_timeout)
  4. if OPTIONS: read response, return
  5. if preview:
       wait for "100 Continue" or early final response (continue_timeout)
       if 100 Continue: write remaining body + zero chunk
  6. read response bytes
  7. parse_icap_response(raw) → ParsedResponse
       parse_icap_response_head → status, headers
       dechunk_response_body_if_needed → dechunked body
  8. store / release Conn based on ConnectionPolicy
```

Streaming variant (`send_streaming_reader`) skips step 2 body buffering — the
body is written chunk-by-chunk from an `AsyncRead` source after the headers.

### Server accept loop

```
ServerBuilder::build() → Server (binds TcpListener)

Server::run()
  loop:
    accept TCP connection
    check connection semaphore → 503 if over limit
    tokio::spawn(handle_connection(socket, …))

handle_connection(socket, routes, aliases, …)
  loop (keep-alive):
    1. read until CRLFCRLF (idle_keepalive / header_read timeouts)
    2. parse_icap_request(raw, mode) → IncomingRequest
         parse_icap_request_with_mode:
           parse request line + ICAP headers
           validate Host + Encapsulated presence
           parse Encapsulated offsets
           parse embedded HTTP head
           read + dechunk embedded body
    3. resolve_service(path, aliases, default_service)
    4. route lookup → RouteEntry for service
       unknown service → 404
       unsupported method → 405
       OPTIONS → ServiceOptions::build_response_for(req)
    5. if preview flag present:
         read preview bytes up to Preview: N limit
         mark body as Body::Preview { bytes, ieof, remainder }
         call handler (preview-aware route)
         if PreviewDecision::Respond(resp): write response, continue loop
         if PreviewDecision::Continue:
           send "ICAP/1.0 100 Continue" (write_timeout)
           read remainder body (body_read timeout)
           convert body to Body::Full
           call handler again with full body
    6. call handler → HandlerResult<Response>
       HandlerError → error response (status from HandlerError)
    7. guard 204: if Allow:204 absent and no preview → wrap as 200 with echoed body
    8. response.to_raw() → wire bytes
    9. write response (write_timeout)
   break on non-keep-alive or error
```

---

## Protocol details

### Chunked framing

ICAP wraps embedded entity bodies in HTTP/1.1-style chunked encoding.
`protocol/chunked.rs` provides the read path (`parse_one_chunk`,
`read_chunked_to_end`) and write path (`write_chunk`, `write_chunk_into`).

The `;ieof` chunk extension (RFC 3507 §4.5) signals that the preview is the
complete body — no `100 Continue` is needed. `parse_one_chunk_meta` detects
this flag; `write_chunk_into` does not emit it (callers handle the terminator).

### Encapsulated header

`Encapsulated:` lists named byte offsets into the area that follows ICAP
headers. `Encapsulated` struct holds up to six optional offsets: `req_hdr`,
`res_hdr`, `req_body`, `res_body`, `opt_body`, `null_body`. All offsets are
relative to the first byte after the ICAP `\r\n\r\n`.

`parse_encapsulated_value` detects duplicates and monotonicity violations.
`validate_encapsulated_for_method` checks method-specific invariants (e.g.,
REQMOD must not carry `res-hdr`).

### ISTag

RFC 3507 requires ISTag to be a quoted-string ≤ 32 characters. `validate_istag`
accepts:
- Quoted-string form: `"value"` (backslash escaping allowed, content visible ASCII)
- Unquoted base64-like token: letters, digits, `+`, `/`, `=`, `-`, `.`, `_`, `#`

`istag_header_value` auto-quotes unquoted values for wire output. The parser is
more permissive than the serializer for compatibility with c-icap and similar
implementations.

### Preview: 0 fast-path

`preview_ieof = true` on a `Request` causes the client to send `0; ieof\r\n\r\n`
instead of `0\r\n\r\n`. This tells the server the preview is the entire body,
allowing a `204 No Content` response without `100 Continue`. Validated by
`validate_for_send`: `preview_ieof` requires `preview_size == Some(0)`.

---

## Service routing

```
resolve_service(raw_path, aliases, default_service)
  1. if path is "" or "/" and default_service is set → use default
  2. apply alias table (up to 4 rewrites to break cycles)
  3. return resolved name (borrowed from input or owned alias target)
```

Route lookup returns a `RouteEntry` containing:
- `handlers: HashMap<Method, HandlerEntry>` — one entry per ICAP method
- `options: Option<ServiceOptions>` — OPTIONS response configuration

`HandlerEntry` wraps the async handler closure and a `preview_aware: bool` flag
(derived from the return type via the `RouteOutput` trait).

`RouteOutput` is a sealed trait implemented for:
- `HandlerResult<Response>` — `PREVIEW_AWARE = false`
- `HandlerResult<PreviewDecision>` — `PREVIEW_AWARE = true`

---

## TLS (feature: `tls-rustls`)

`Conn` in `net.rs` is a pin-projected enum:

```
Conn
  Plain(TcpStream)
  Rustls(TlsStream<TcpStream>)   ← only when tls-rustls feature is active
```

Both variants implement `AsyncRead + AsyncWrite`. Client code calls
`Conn::plain_mut()` to access the raw TCP socket when it needs to peek for
an early response before sending headers.

`ClientTlsConfig` builds lazily (crypto provider is installed on first `build()`
call). `ServerTlsConfig` can be constructed from PEM bytes or file paths. Both
support mTLS via `with_client_auth_pem*` helpers.

The global rustls crypto provider is installed once via a `OnceLock` in
`tls::ensure_crypto_provider()`, preferring `aws-lc-rs` and falling back to
`ring`.

---

## Testing

Integration tests live in `icap-rs/tests/`:

| File | Coverage |
|---|---|
| `rfc3507.rs` | RFC §-labelled compliance tests (request parsing, response parsing, preview, ISTag, Encapsulated) |
| `server.rs` | End-to-end server routing, alias/default, 404/405 |
| `preview.rs` | Preview handshake, ieof fast-path, PreviewDecision variants |
| `streaming_response_writer.rs` | Streaming response body from handler |
| `client_graceful_shutdown.rs` | RFC §4.2 — `Connection: close` emitted by client on `ConnectionPolicy::Close`; server closes after responding when header is present |
| `client_keep_alive.rs` | Keep-alive connection reuse across multiple requests |
| `client_timeout.rs` | Client-side timeout enforcement |
| `early_response.rs` | Early 503 when server connection limit is exceeded |
| `max_connections.rs` | Global connection limit enforcement and OPTIONS advertisement |
| `tls.rs` | TLS (rustls) feature tests |

All integration tests use `tests/common/` helpers:
- `find_free_port()` — bind port 0 and release, return the OS-assigned port
- `wait_port_ready(addr)` — poll TCP connect until the server is listening

Unit tests live inline in each source module (`#[cfg(test)]`).

---

## Constants

| Constant | Value | Purpose |
|---|---|---|
| `MAX_HDR_BYTES` | 64 KiB | Maximum ICAP header block size |
| `ICAP_VERSION` | `"ICAP/1.0"` | Protocol version string used in request/response lines |
| `LIB_VERSION` | from `Cargo.toml` | Exposed for `User-Agent` headers |
| `DEFAULT_ICAP_PORT` | `1344` | Default port for `icap://` URIs |
| `DEFAULT_ICAPS_PORT` | `11344` | Default port for `icaps://` URIs |
| `DEFAULT_HANDSHAKE_TIMEOUT` | `10s` | TLS handshake deadline |
