# Changelog

## Unreleased

### Added

- Client-side OPTIONS response cache (RFC 3507 §4.10 / §5), opt-in via `ClientBuilder::with_options_cache(OptionsCacheConfig)`. Lifetime is taken from the response `Options-TTL` header, falling back to `OptionsCacheConfig::default_ttl`; with neither, the response is not cached. A changed `ISTag` observed on a later `REQMOD`/`RESPMOD` response invalidates the entry, and `Client::invalidate_options_cache()` clears every entry on demand (#15).
- Client-side `Transfer-Preview` / `Transfer-Ignore` / `Transfer-Complete` policy (RFC 3507 §4.10.2). When the OPTIONS cache is enabled, the client resolves the per-extension transfer action from the cached OPTIONS response: `Transfer-Ignore` returns a synthetic `204` without contacting the server, `Transfer-Complete` sends the full body with no `Preview` header, and `Transfer-Preview` sends the advertised preview window before `100 Continue` (#16, #19).
- Client proxy authentication (RFC 3507 §7.1), opt-in via `ClientBuilder::proxy_auth(username, password)`. On `407 Proxy Authentication Required` the client retries the request once with `Proxy-Authorization: Basic <base64(user:pass)>`. New public `ProxyAuth` type (#16, #19).
- New examples: `options_cache_client`, `transfer_policy_client`, `proxy_auth_client`.

### Changed

- Server-injected request metadata (`ISTag`, chunk trailers) moved off the public `Request` field set into `IncomingMeta`, carried through the new sealed `DirectionMeta` trait as `Request<R, D>::meta`. `OutboundRequest` pays zero overhead for these fields; `IncomingRequest` exposes them via `istag()` / `chunk_trailers()` (#18).

### Fixed

- Client response framing on early/single-line error responses: a parsed 4xx/5xx status line no longer terminates the ICAP response while the connection stays open, so error responses whose headers arrive in a later TCP read are not truncated (#15).

## 0.3

### Added

- New top-level `tls` module (`ServerTlsConfig`, `ClientTlsConfig`, `TlsError`) consolidating all Rustls usage; replaces the ad-hoc TLS plumbing previously spread across `server/builder.rs` and `client/tls/*`.
- Server TLS builder with explicit `from_pem` for PEM content, `from_pem_files` for file paths, `with_client_auth_pem` / `with_optional_client_auth_pem` for CA PEM content, file-path variants for both mTLS modes, `with_handshake_timeout`, and `from_rustls_config` escape hatch.
- Client TLS builder with `with_native_roots`, `empty`, PEM-content and PEM-file trust root helpers, PEM-content and PEM-file client auth helpers, `with_sni`, `with_handshake_timeout`, and `from_rustls_config` escape hatch. Client mTLS is now supported.
- Cargo feature `tls-rustls` (bundles the `ring` crypto provider as the default backend) and additive `tls-rustls-aws-lc-rs`; explicit `ensure_crypto_provider()` on first TLS use removes the implicit `install_default()` race.
- Cargo feature `dangerous-insecure-tls` enabling a real `dangerous_disable_cert_verification()` on the client (parity with `c-icap-client -tls-no-verify`), gated behind the feature with a `WARN` log when used.
- TLS handshake timeout enforced on both server (accept loop) and client (`connect`); surfaced as `TlsError::HandshakeTimeout` instead of a generic I/O error.
- Client-side total-operation, TCP connect, write, and Preview continue timeouts via `ClientBuilder`, with matching `rs-icap-client` CLI flags.
- `Error::Tls(TlsError)` variant — TLS failures (handshake, cert verification, PEM parsing, invalid SNI, missing crypto provider) no longer collapse into `Error::Network`.
- `PreviewDecision` route handlers: services may return a final response after the preview bytes or continue with `100 Continue` from the regular route. `route`/`route_reqmod` handlers now return `IcapResult<PreviewDecision>`.
- `Allow: 206` no-modification responses using the `use-original-body` partial-content marker; `rs-icap-client` reconstructs `206 Partial Content` output by appending the original body suffix from the offset.
- RFC 3507 integration conformance matrix (`tests/rfc3507.rs`) covering supported variants and placeholders for unsupported gaps; RFC support plan documented in `docs/rfc3507.md`.
- TLS integration test suite (`tests/tls.rs`): handshake success, cert mismatch, invalid SNI, handshake timeout, mTLS valid/missing client cert, ALPN negotiation, `icaps://` default port, and `dangerous-insecure-tls`.
- New examples: `preview_decision_server`, `streaming_client`, `tls_mtls_client`.
- Benchmarks: expanded `protocol_bench`, new `tls_overhead_bench`, expanded `rps_bench` with keep-alive coverage.
- MIT `LICENSE` file at the workspace root.

### Breaking

- ICAP responses with embedded HTTP now use RFC 3507 framing: `req-hdr`/`res-hdr` bytes are sent unchunked, and ICAP chunked coding starts only at `req-body`/`res-body`/`opt-body`. The previous (invalid) format that chunked `HTTP head + HTTP body` as one block is no longer produced or accepted.
- Response parsing now rejects legacy unchunked entity bytes after a `req-body`/`res-body`/`opt-body` offset. Peers must send an ICAP-chunked entity body at that offset.
- `ServerBuilder` TLS API replaced: `with_tls_from_pem_files` and `with_mtls_from_pem_files` removed in favour of `with_tls(ServerTlsConfig)`. The internal `TlsParams` type is gone.
- `ClientBuilder` TLS API replaced: `use_rustls`, `danger_disable_cert_verify` (which was a documented no-op), `sni_hostname`, and the old builder-level root-CA helper removed in favour of `with_tls(ClientTlsConfig)`. The `TlsBackend` enum is removed.
- OpenSSL backend stubs removed entirely (`client/tls/openssl.rs`, commented `use_openssl` paths in `net.rs`/`client/builder.rs`).
- `ServerBuilder::route_preview` removed; preview-time decisions belong to regular `route`/`route_reqmod` handlers returning `IcapResult<PreviewDecision>`.
- Strict request parser now requires `Encapsulated` for all methods (including `OPTIONS`); legacy peers must opt into compatibility mode explicitly.
- Method-specific `Encapsulated` forms are validated; `null-body` mixed with body tokens is rejected.
- `ServiceOptions` fields are now `pub(crate)`; only the builder API is public. `ISTag` is mandatory — `ServiceOptions` no longer silently defaults to `ISTag "default"`, and the server now returns an internal error if it is unconfigured. Tests/services must call `with_static_istag(...)` (or a dynamic ISTag source).
- `ServiceOptions::build_response_for()` now returns `IcapResult<Response>` and propagates ISTag resolution errors.
- Server route handlers receive `IncomingRequest` (not the outbound `Request` builder) — prevents handlers from rewriting the ICAP request line, headers, preview state, or `Allow` flags after parsing. Use `embedded_mut()` / `into_embedded()` to adapt encapsulated HTTP.
- Public ICAP `Request`/`Response` API reworked for ergonomics (`try_new`, `with_http_request`/`with_http_response`, head-only variants for streaming). The previous shape is not preserved.
- Parser module split: `parser::icap`/`parser::wire`/`parser::http_embed` removed; protocol parsing lives under `icap_rs::protocol` (`chunked`, `encapsulated`, `headers`, `http_embed`, `istag`).
- Server module split: `server.rs` is now a thin entrypoint; logic lives in `server/{builder,connection,errors,no_modification,options,preview,router}.rs`.

### Fixed

- Server now returns ICAP `400 Bad Request` for malformed wire requests and `501 Not Implemented` for unknown methods, instead of dropping the connection.
- TLS handshake errors on the server are no longer reported as generic I/O errors; they are classified through `TlsError` and overload (503/connection-limit) is now decided **before** the TLS handshake so a connection-flood does not consume handshake CPU.
- `Client` and `Response::from_raw` now read RFC-compliant embedded HTTP responses as `Response.body = HTTP head + dechunked HTTP body`, without chunk-size metadata leaking into the body.
- Null-body request parsing and ISTag compatibility (#10, #8).
- PEM private key loader now accepts PKCS#8, PKCS#1, and SEC1 EC keys via `rustls_pemfile::private_key()` (previously SEC1 EC was silently skipped).
- Streaming preview flow corrected (no premature termination, correct `ieof`/`100 Continue` interaction).
- Embedded HTTP start-line validation and shared `Encapsulated` parsing reused on the response path.

### Performance

- Connection keep-alive buffer: `buf_start` offset replaces per-request `Vec::drain`, eliminating O(N) memmoves on the hot path; full O(1) `clear()` when the buffer is fully consumed.
- Preview path no longer clones the entire connection buffer; a targeted parse buffer is built from two `extend_from_slice` calls (ICAP headers + dechunked preview).
- Header text is borrowed as `&str` rather than allocated via `to_string()`; zero allocation per request for header parsing.
- Oversized-header guard: connections sending unbounded headers now receive `400 Bad Request` instead of growing the buffer.
- `ServiceOptions::set_methods()` pre-formats and caches the `Methods` string; `OPTIONS` responses no longer allocate a `Vec<String> + join` per request.
- `CursorReader` performs zero-copy reads into Tokio `ReadBuf` by slicing the cursor's backing bytes directly, removing two intermediate copies.

### Docs

- New `docs/tls.md` TLS/ICAPS guide (ports, features, server/client config, mTLS, insecure mode).
- New `docs/rfc3507.md` RFC support matrix.
- Library `README.md` rewritten: feature flags, API surface, common API paths, TLS section, examples list.
- Workspace `README.md` updated with crate inventory and supported/partial/not-implemented protocol areas.
- `rs-icap-client` README updated for the current CLI flags (Preview, `Allow: 204/206`, ICAPS, streaming).
- Inline rustdoc examples in `docs/tls.md` corrected: `IncomingRequest` handler type, `status_code()`/`status_text()` accessor calls, `#[cfg(feature = "tls-rustls")]` guards.

### Internal

- Workspace migrated to a shared `[workspace.package]` / `[workspace.dependencies]` block; member crates inherit `edition`, `repository`, `license`, `keywords`, and `categories`.
- Workspace lints tightened (`clippy::pedantic`, `clippy::nursery`, `clippy::cargo`, `unsafe_code = "forbid"`).
- Dependencies bumped (#6) and manifests cleaned up.
