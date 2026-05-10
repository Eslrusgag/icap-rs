# ICAP in Rust

This repository contains a set of Rust crates for working with the ICAP
protocol ([RFC 3507](https://datatracker.ietf.org/doc/html/rfc3507)).

## Crates

### `icap-rs`

Core ICAP library providing protocol primitives.

### `rs-icap-client`

Command-line ICAP client inspired by `c-icap-client`.

### `rs-icap-server`

ICAP server implementation inspired by `c-icap`.

## Implemented

### Core protocol

- [x] ICAP over TCP
- [x] ICAP/1.0 parsing and validation
- [x] `OPTIONS`
- [x] `REQMOD`
- [x] `RESPMOD`
- [x] Required `Host` header
- [x] Case-insensitive headers
- [x] Keep-alive connections without pipelining
- [x] Basic `Encapsulated` parsing and validation
- [x] Embedded HTTP request support
- [x] Embedded HTTP response support
- [x] Chunked encapsulated request body handling
- [x] Server-side dechunking
- [x] Preview support
- [x] `Preview: 0`
- [x] `Preview: N`
- [x] `ieof`
- [x] `100 Continue` preview flow
- [x] `204 No Content`
- [x] `ISTag` validation
- [x] OPTIONS capability responses
- [x] `Max-Connections`
- [x] Early `503 Service Unavailable`
- [x] TLS / ICAPS support (`icaps://`)
- [x] TLS listener support
- [x] mTLS support

### Client

- [x] Build and send `OPTIONS`
- [x] Build and send `REQMOD`
- [x] Build and send `RESPMOD`
- [x] Streaming uploads
- [x] Keep-alive connection reuse
- [x] Preview negotiation
- [x] `Allow: 204`
- [x] `Allow: 206` flag parsing
- [x] ICAPS client support

### Server

- [x] Async TCP listener
- [x] `REQMOD` routing
- [x] `RESPMOD` routing
- [x] Automatic OPTIONS responses
- [x] Preview wire-level handshake
- [x] Embedded HTTP parsing
- [x] Connection limiting
- [x] TLS server support

### Tests

- [x] Keep-alive tests
- [x] Preview tests
- [x] Max connections tests
- [x] Early response tests
- [x] Header parser tests
- [x] Encapsulated parser tests

---

## Partially Implemented / Needs Improvement

- [ ] RFC-compliant ICAP response framing for embedded HTTP
- [ ] RFC-compliant response reader for embedded HTTP
- [ ] Strict RFC parser mode
- [ ] Compatibility parser mode
- [ ] Preview-aware handler API
- [ ] Early final response before `100 Continue`
- [ ] Proper ICAP `400 Bad Request`
- [ ] Proper ICAP `405 Method Not Allowed`
- [ ] Proper ICAP `501 Not Implemented`
- [ ] Full method-specific `Encapsulated` validation
- [ ] Full `Allow: 206` semantics
- [ ] Automatic `Transfer-Preview` handling
- [ ] Automatic `Transfer-Ignore` handling
- [ ] Automatic `Transfer-Complete` handling
- [ ] Cache semantics for `ISTag` and `Options-TTL`
- [ ] Automatic HTTP hop-by-hop header handling
- [ ] Full service URI semantics
- [ ] Structured trailer header support
- [ ] Preview-aware streaming decisions
- [ ] Better external interoperability support

---

## Not Implemented Yet

- [ ] ICAP `Upgrade` TLS negotiation
- [ ] Built-in ICAP authentication / authorization
- [ ] Full RFC cache model
- [ ] Strict ABNF validation mode
- [ ] Full wire-level RFC conformance suite
- [ ] External ICAP interoperability fixture suite
- [ ] Golden serialization tests
- [ ] Golden wire-level response tests

---

## Project Goals

- [x] Practical ICAP implementation in Rust
- [x] Async-first architecture
- [x] Idiomatic Rust APIs
- [x] Real-world interoperability
- [ ] Stronger RFC 3507 compliance
- [ ] Full protocol conformance testing
- [ ] Production-grade interoperability coverage