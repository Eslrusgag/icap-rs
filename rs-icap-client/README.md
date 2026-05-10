# rs-icap-client

`rs-icap-client` is a command-line ICAP client built on top of the `icap-rs`
library. It supports `OPTIONS`, `REQMOD`, `RESPMOD`, Preview negotiation,
streaming uploads, `Allow: 204`, `Allow: 206`, and direct ICAPS through Rustls.

The workflow is intentionally close to `c-icap-client`: providing `-f` defaults
to `RESPMOD`, and providing `--req` selects `REQMOD` unless `--method` is set.

## Build

The CLI enables `tls-rustls` by default:

```bash
cargo build -p rs-icap-client --release
```

Build without TLS:

```bash
cargo build -p rs-icap-client --release --no-default-features
```

Build without default features but enable TLS explicitly:

```bash
cargo build -p rs-icap-client --release --no-default-features --features tls-rustls
```

Run from the workspace:

```bash
cargo run -p rs-icap-client -- -u icap://127.0.0.1:1344/respmod -m OPTIONS -v
```

## Usage

```text
rs-icap-client [OPTIONS]
```

### Connection and Method

- `-u, --uri <URI>`: full ICAP URI, for example
  `icap://host[:port]/service` or `icaps://host[:port]/service`.
  Default: `icap://127.0.0.1:1344/`.
- `-m, --method <METHOD>`: ICAP method: `OPTIONS`, `REQMOD`, or `RESPMOD`.
- `-t, --timeout <SECS>`: client read timeout in seconds. By default no read
  timeout is applied.
- `-d, --debug-level <LEVEL>`: enable logs, where higher values are more
  verbose.

### Payload

- `-f, --filename <FILE>`: send this file to the ICAP server. If no method is
  specified, this selects `RESPMOD`.
- `-o, --output <FILE>`: save the response body to a file. By default the body
  is written to stdout.
- `--stream-io`: stream the file body instead of buffering it in memory.

### ICAP Semantics

- `--req <URL>`: send `REQMOD` with the given HTTP request URL.
- `--resp <URL>`: annotate `RESPMOD` with a source URL.
- `-w, --preview-size <N>`: force `Preview: N`.
- `--ieof`: with `--preview-size 0`, send `0; ieof`.
- `--nopreview`: force `Preview: 0` without `ieof`.
- `--no204`: do not advertise `Allow: 204` outside preview flow.
- `--206`: advertise `Allow: 206` and accept partial-content
  no-modification responses using `use-original-body`.
- `--noreshdr`: compatibility no-op kept for parity with `c-icap-client`.

### Headers

- `-x, --xheader "Header: Value"`: add an ICAP header. Repeatable.
- `--hx "Header: Value"`: add an embedded HTTP request header. Repeatable.
- `--rhx "Header: Value"`: add an embedded HTTP response header. Repeatable.

### TLS

These options are effective only for `icaps://` URIs.

- `--tls-backend rustls`: select the Rustls backend.
- `--tls-ca <PEM_FILE>`: add an extra CA bundle to the Rustls trust store.
- `--sni <HOSTNAME>`: override SNI and certificate verification name.
- `--insecure`: compatibility flag. With Rustls 0.23 it is ignored; certificate
  verification is not disabled.

### Output and Debugging

- `-v, --verbose`: print parsed ICAP response headers and metadata.
- `-p, --print-request`: print the generated ICAP request and exit.

## Examples

### OPTIONS

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/respmod \
  -m OPTIONS \
  -v
```

### REQMOD

If `--preview-size` is not provided, the client first probes server
capabilities with `OPTIONS` and then sends the modifying request.

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/scan \
  --req http://origin.example/
```

### REQMOD with `Preview: 0` and `ieof`

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/scan \
  --req http://origin.example/ \
  --preview-size 0 \
  --ieof
```

### RESPMOD from a File

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/respmod \
  --resp http://origin.example/page.html \
  -f ./page.html \
  -v
```

### Streaming RESPMOD

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/respmod \
  --resp http://origin.example/big.zip \
  -f ./big.zip \
  --stream-io \
  --preview-size 0
```

### Advertise `Allow: 206`

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/respmod \
  --resp http://origin.example/page.html \
  -f ./page.html \
  --206 \
  -v
```

### Print the ICAP Request

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/scan \
  --req http://origin.example/ \
  --print-request
```

### ICAPS with a Local CA

```bash
cargo run -p rs-icap-client -- \
  -u icaps://localhost:11344/scan \
  --tls-backend rustls \
  --tls-ca test_data/certs/ca.crt \
  --sni localhost \
  -m OPTIONS \
  -v
```

## Behavior Notes

- `icap://` defaults to port `1344`.
- `icaps://` defaults to port `11344`.
- Header names are case-insensitive. Printed ICAP headers use canonical names
  such as `Encapsulated`, `ISTag`, and `Preview`.
- With `--stream-io` or `Preview: 0`, the client sends the request head and
  preview marker, waits for `100 Continue`, and then streams the remaining file
  body.
- If neither `Allow: 204` nor Preview is used, an RFC-aware server may avoid
  `204 No Content` and return an encapsulated `200 OK` response instead.
- `--206` allows a no-modification response to preserve the original body
  suffix via the `use-original-body` marker.

## Related Documentation

- [`icap-rs` library guide](../icap-rs/README.md)
- [TLS and ICAPS](../icap-rs/docs/tls.md)
- [RFC 3507 support matrix](../icap-rs/docs/rfc3507.md)
