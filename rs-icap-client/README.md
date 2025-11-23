# rs-icap-client

A small but capable **ICAP client CLI** (similar to `c-icap-client`) built on top of the `icap-rs` library.
It speaks `OPTIONS`, `REQMOD`, and `RESPMOD`, supports **Preview** (including `Preview: 0` and `ieof`),
and can stream large bodies after `100 Continue`. TLS (**ICAPS**) is supported via **rustls**.

---

## Features

- ICAP methods: `OPTIONS`, `REQMOD`, `RESPMOD`
- **Preview** negotiation (incl. `Preview: 0` and optional `ieof` fast‑204 path)
- Streaming bodies from file after `100 Continue`
- Custom ICAP and embedded HTTP headers
- Optional connection/read timeout
- **TLS / ICAPS** via `rustls` (when built with the appropriate cargo features)
- c-icap compatible workflow: defaults to RESPMOD when `-f` is provided, REQMOD when `--req` is set

---

## Install / Build

This binary lives in the `examples` (or a sub-crate) of the repository and uses the `icap-rs` library.

```bash
# Plain (no TLS):
cargo build --release

# With TLS (rustls + ring provider):
cargo build --release --features "tls-rustls tls-rustls-ring"

# Or: rustls with aws-lc provider
cargo build --release --features "tls-rustls tls-rustls-aws-lc"
```

> **Note on TLS**  
> `icaps://` requires building with `tls-rustls` (pick exactly one provider: `tls-rustls-ring` **or**
`tls-rustls-aws-lc`).  
> If you run the tool against an `icaps://…` URI without these features, the program will refuse to run.

---

## Usage

```text
rs-icap-client [OPTIONS]
```

### Core options

- `-u, --uri <URI>` — Full ICAP URI, e.g. `icap://host[:port]/service` or `icaps://host[:port]/service`  
  *Default:* `icap://127.0.0.1:1344/`
- `-m, --method <METHOD>` — One of `OPTIONS|REQMOD|RESPMOD` (auto‑selected if omitted)
- `-f, --filename <FILE>` — Read body from file (defaults workflow to RESPMOD, like c-icap-client)
- `-o, --output <FILE>` — Save ICAP response body to this file (default: stdout)
- `-t, --timeout <SECS>` — Client read timeout in seconds (no timeout by default)

### ICAP semantics

- `--req <URL>` — Send **REQMOD** for the given request URL (origin‑form or absolute)
- `--resp <URL>` — Annotate **RESPMOD** with a source URL (X-Resp-Source header)
- `-w, --preview-size <N>` — Force explicit Preview size
- `--ieof` — With `--preview-size 0`, send the `ieof` fast‑204 hint
- `--nopreview` — Shortcut for `Preview: 0` (no `ieof`); useful with `--stream-io`
- `--no204` — Do **not** advertise `Allow: 204`
- `--206` — Advertise/accept `Allow: 206`
- `--stream-io` — Do not buffer the file; stream chunks after `100 Continue`

### Headers

- `-x, --xheader "Header: Value"` — Extra ICAP headers (repeatable)
- `--hx "Header: Value"` — Extra **HTTP request** headers (repeatable)
- `--rhx "Header: Value"` — Extra **HTTP response** headers (repeatable)

### TLS (ICAPS) options (rustls)

These are effective only when URI starts with `icaps://` **and** the binary is built with `tls-rustls`.

- `--tls-backend rustls` — Select rustls (only valid choice for this build)
- `--tls-ca <PEM_FILE>` — Add a local CA bundle (PEM) to rustls trust store (for self‑signed/testing)
- `--sni <HOSTNAME>` — Override SNI used during TLS handshake
- `--insecure` — Attempt to disable certificate verification  
  *Note:* rustls **0.23** doesn’t expose a public “no-verify” API; this flag may be ignored when using rustls.

### Output & debug

- `-v, --verbose` — Print parsed ICAP response headers and metadata
- `-p, --print-request` — Print **exact ICAP wire** that would be sent, then exit
- `-d, --debug-level <1..5>` — Enable logs (1=errors … 5=trace)
---

## Examples

### 1) Basic `OPTIONS`

```bash
rs-icap-client -u icap://127.0.0.1:1344/options -v -d 3
```

### 2) `REQMOD` with Preview autodetection

If you don’t force `--preview-size`, the client first negotiates using `OPTIONS` and then sends REQMOD.

```bash
rs-icap-client -u icap://127.0.0.1:1344/scan \
  --req http://example.com/
```

### 3) `REQMOD` with explicit `Preview: 0` + `ieof`

```bash
rs-icap-client -u icap://127.0.0.1:1344/scan \
  --req http://example.com/ -w 0 --ieof
```

### 4) `RESPMOD` from a file (buffered in memory)

```bash
rs-icap-client -u icap://127.0.0.1:1344/respmod \
  --resp http://example.com/page.html \
  -f ./page.html -v
```

### 5) `RESPMOD` streaming a large file (no buffering)

```bash
rs-icap-client -u icap://127.0.0.1:1344/respmod \
  --resp http://example.com/big.zip \
  -f ./big.zip --stream-io -w 0
```

### 6) Print the exact ICAP request (dry‑run)

```bash
rs-icap-client -u icap://127.0.0.1:1344/scan \
  --req http://example.com/ \
  -p
```

### 7) ICAPS (TLS) with a local CA and custom SNI

First, build with rustls:

```bash
cargo build --release --features "tls-rustls tls-rustls-ring"
# or: --features "tls-rustls tls-rustls-aws-lc"
```

Then run:

```bash
rs-icap-client -u icaps://localhost:2346/test \
  --tls-backend rustls \
  --tls-ca /path/to/ca.crt \
  --sni localhost \
  -v -d 4
```

> If your server uses a self‑signed certificate, add its **CA** via `--tls-ca`.  
> `--insecure` may be ignored with rustls 0.23 and is not recommended for production.

---

## Notes & behavior

- When neither `Allow: 204` nor `Preview` is used, some ICAP servers will *not* return `204`.  
  The companion `icap-rs` server, for example, returns `200` and echoes the embedded HTTP message.
- With `--stream-io` (or `Preview: 0`), the client sends headers + preview and waits for `100 Continue` before
  streaming file chunks.
- Header names are case‑insensitive; when printing, ICAP header names are canonicalized (`Encapsulated`, `ISTag`, etc.).

---

## License

Same license as the parent `icap-rs` project (see the repository for details).
