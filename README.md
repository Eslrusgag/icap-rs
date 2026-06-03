# icap-rs

Rust crates for building ICAP/1.0 clients and services, with protocol behavior
guided by [RFC 3507](https://www.rfc-editor.org/rfc/rfc3507).

The project favors explicit wire-level behavior over hidden compatibility
magic: malformed ICAP requests should become protocol errors, unsupported RFC
features should be visible, and compatibility modes should be documented and
tested.

## Crates

| Crate | Status | Purpose |
| --- | --- | --- |
| [`icap-rs`](icap-rs/README.md) | Active | Core library with client APIs, server APIs, ICAP request/response types, parsers, serializers, Preview handling, embedded HTTP support, and optional Rustls-based ICAPS. |
| [`rs-icap-client`](rs-icap-client/README.md) | Active | CLI ICAP client for `OPTIONS`, `REQMOD`, and `RESPMOD`, including Preview, streaming uploads, `Allow: 204`, `Allow: 206`, and ICAPS. |
| `rs-icap-server` | Placeholder binary | Workspace member reserved for a standalone server binary. The usable server implementation currently lives in the `icap-rs` library API. |

## Supported Protocol Areas

- ICAP/1.0 request and response serialization/parsing.
- `OPTIONS`, `REQMOD`, and `RESPMOD`.
- Required `Host` header validation.
- Case-insensitive ICAP header lookup and canonical wire output.
- Method-specific `Encapsulated` validation.
- Embedded HTTP request and response heads/bodies. `RESPMOD` requests may
  include the originating HTTP request headers (`req-hdr`, RFC 3507 §4.4.1):
  `Request::with_http_response_and_request_context` on the client path;
  `EmbeddedHttp::respmod_request_head` on the server path.
- RFC 3507 response framing: embedded HTTP heads are unchunked; encapsulated
  entity bodies use ICAP chunked framing.
- Preview flows, including `Preview: 0`, `ieof`, and `100 Continue`.
- Server-side preview-aware handlers that may return a final response before
  `100 Continue`.
- `204 No Content` guard behavior for requests that do not advertise `Allow:
  204` and do not use Preview.
- `206 Partial Content` no-modification responses using the
  `use-original-body` marker.
- `ISTag` validation for successful ICAP responses.
- Keep-alive connection reuse without pipelining.
- Client-side OPTIONS response caching with `Options-TTL` lifetime and `ISTag`
  invalidation (RFC 3507 §4.10 / §5), opt-in via
  `ClientBuilder::with_options_cache`.
- Client-side `Transfer-Preview` / `Transfer-Ignore` / `Transfer-Complete`
  policy applied per file extension from a cached `OPTIONS` response
  (RFC 3507 §4.10.2).
- Client `Proxy-Authorization: Basic` retry on `407 Proxy Authentication
  Required` (RFC 3507 §7.1), opt-in via `ClientBuilder::proxy_auth`.
- Configurable ICAP request/response header limits via
  `ServerBuilder::with_request_header_limit` and
  `ClientBuilder::with_response_header_limit`.
- Per-service embedded HTTP body limits via `ServiceOptions::with_max_object_size`;
  the limit is advertised as `Max-Object-Size` in `OPTIONS` and enforced using
  decoded ICAP chunked body bytes rather than trusting embedded HTTP
  `Content-Length`.
- Direct ICAPS (`icaps://`) via Rustls when the `tls-rustls` feature is
  enabled.
- TLS listener and mTLS support in the library server API.

See [`icap-rs/docs/rfc3507.md`](icap-rs/docs/rfc3507.md) for the RFC-oriented
support matrix and known gaps.

## Partial or Explicit Compatibility Behavior

- `OPTIONS` without `Encapsulated` is rejected by the strict request parser.
  The server can opt into a compatibility request parser for legacy peers.
- Incoming client responses accept legacy `204 No Content` responses without
  `Encapsulated` as equivalent to `Encapsulated: null-body=0` for c-icap
  interoperability.
- Client-side `Transfer-*` policy and OPTIONS caching are opt-in: without
  `ClientBuilder::with_options_cache` the client never fetches `OPTIONS`
  automatically and applies no transfer policy. The server always advertises
  the `Transfer-*` and cache headers configured on its `ServiceOptions`.
- Service routing is currently based on the resolved service path segment, not
  the full RFC service URI identity model.
- Chunk extensions used by supported flows are parsed, but structured trailer
  headers do not have a first-class API.

## Not Implemented

- RFC 3507 `Upgrade` TLS negotiation. Use direct `icaps://` instead.
- Server-side ICAP authentication enforcement. The client sends
  `Proxy-Authorization` on `407` (RFC 3507 §7.1), but the server does not
  challenge or verify credentials.
- Full RFC cache model. Core OPTIONS caching and `ISTag` invalidation are
  implemented; some advanced cache semantics are not.
- Full structured trailer API.
- Complete external interoperability fixture suite.

## Quick Start

Build the workspace:

```bash
cargo build --workspace
```

Run the library example server:

```bash
cargo run -p icap-rs --example server
```

Send an `OPTIONS` request with the CLI:

```bash
cargo run -p rs-icap-client -- -u icap://127.0.0.1:1344/respmod -m OPTIONS -v
```

Run the Squid interoperability demo:

```bash
cargo run -p icap-rs --example squid_interop_server
docker compose -f interop/squid/compose.yaml up
curl -v -x http://127.0.0.1:3128 http://origin/
```

Run the c-icap interoperability demo for the Rust client:

```bash
docker compose -f interop/c-icap/compose.yaml up --build
cargo run -p rs-icap-client -- -u icap://127.0.0.1:1345/echo -m OPTIONS -v
```

Build with TLS support:

```bash
cargo build --workspace --all-features
```

## Documentation

- [`icap-rs` library guide](icap-rs/README.md)
- [`rs-icap-client` CLI guide](rs-icap-client/README.md)
- [`Squid interoperability demo`](interop/squid/README.md)
- [`c-icap client interoperability demo`](interop/c-icap/README.md)
- [`TLS and ICAPS`](icap-rs/docs/tls.md)
- [`RFC 3507 support matrix`](icap-rs/docs/rfc3507.md)
- [`CHANGELOG.md`](CHANGELOG.md)
