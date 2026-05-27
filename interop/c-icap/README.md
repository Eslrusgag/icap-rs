# c-icap Interoperability Demo

This demo runs a third-party ICAP server, `c-icap`, in Docker and uses
`rs-icap-client` from this workspace to verify client interoperability.

The c-icap server listens inside Docker on port `1344`; compose publishes it on
host port `1345` so it does not conflict with the local `icap-rs` example
server.

## Run

Build and start c-icap:

```bash
docker compose -f interop/c-icap/compose.yaml up --build
```

## Check `OPTIONS`

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1345/echo \
  -m OPTIONS \
  -v
```

Expected signal:

- ICAP status is `200 OK`.
- The response comes from c-icap, not from `icap-rs`.
- Headers should advertise the `echo` service capabilities.

## Check `REQMOD`

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1345/echo \
  --req http://origin.example/ \
  -v
```

Expected signal:

- The request reaches c-icap's `echo` service.
- c-icap returns `ICAP/1.0 204 Unmodified` without an `Encapsulated` header.
- The Rust client should accept that legacy c-icap response as no modification,
  equivalent to `Encapsulated: null-body=0`.

Print the generated request without sending it:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1345/echo \
  --req http://origin.example/ \
  --print-request
```

## Check `RESPMOD`

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1345/echo \
  --resp http://origin.example/ \
  -f interop/squid/origin/index.html \
  -v
```

Expected signal:

- The request reaches c-icap's `echo` service.
- c-icap may return `ICAP/1.0 204 Unmodified` without an `Encapsulated` header
  when `Allow: 204` is advertised.
- The Rust client should complete without protocol errors.

## Why c-icap

c-icap is an independent ICAP implementation commonly used with Squid. Passing
these checks is useful because it validates the client against a real external
server instead of only testing `icap-rs` client and server together.
