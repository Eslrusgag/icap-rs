# TLS and ICAPS

`icap-rs` supports direct ICAP over TLS (`icaps://`) through Rustls when the
`tls-rustls` feature is enabled.

> RFC 3507 does not define ICAPS. The spec briefly references RFC 2817-style
> `Upgrade` negotiation but does not standardize it, and real-world
> deployments use direct ICAPS on TCP port **11344** instead. The
> `Upgrade: TLS` handshake is intentionally **not** implemented; use direct
> `icaps://` listeners and clients.

## Cargo Features

```toml
# Default rustls backend (ring crypto provider — no C toolchain required).
icap-rs = { version = "0.3.0", features = ["tls-rustls"] }
```

`tls-rustls-aws-lc-rs` is an additive opt-in that also compiles the
`aws-lc-rs` provider. When both are compiled in, `aws-lc-rs` is installed
as the default at runtime.

The `tls-rustls` umbrella enables:

- client-side `icaps://` connections,
- Rustls-backed server listeners,
- server-side mTLS,
- loading extra trust roots and a client certificate from PEM data or files,
- a runtime opt-in to disable server certificate verification
  (mirrors `c-icap-client -tls-no-verify`).

Without `tls-rustls`, using an `icaps://` URI returns an error.

## Crypto Provider

rustls 0.23 requires an installed
[`CryptoProvider`](https://docs.rs/rustls/0.23/rustls/crypto/struct.CryptoProvider.html).
The crate installs one lazily the first time TLS is used:

- With the default `tls-rustls` feature, `ring` is installed.
- With `tls-rustls-aws-lc-rs` enabled, aws-lc-rs is installed instead.

If both providers are compiled in, aws-lc-rs is preferred. Applications that
need to control provider selection can call
`rustls::crypto::*::default_provider().install_default()` before constructing
any TLS client or server config.

## Default Ports

| Scheme | Default port |
| --- | --- |
| `icap://`  | 1344 (RFC 3507) |
| `icaps://` | 11344 (project convention; not registered by RFC 3507) |

## Client ICAPS

The simplest case — trust platform CAs, use the URI host as SNI:

```rust,ignore
use icap_rs::{Client, Request};

#[cfg(feature = "tls-rustls")]
#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icaps://icap.example:11344/respmod")?
        .build();

    let response = client.send(&Request::options("respmod")).await?;
    println!("ICAP {} {}", response.status_code().as_u16(), response.status_text());
    Ok(())
}
```

### Custom CA Bundle

For self-signed deployments, supply a CA bundle through `ClientTlsConfig`.
The primary API accepts PEM content, so callers can load it from config,
secrets storage, environment variables, or any other source:

```rust,ignore
use icap_rs::{Client, Request};
use icap_rs::tls::ClientTlsConfig;

#[cfg(feature = "tls-rustls")]
#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let ca_pem = std::fs::read_to_string("test_data/certs/ca.pem")?;

    let tls = ClientTlsConfig::with_native_roots()
        .add_root_ca_pem(ca_pem)?
        .with_sni("localhost");

    let client = Client::builder()
        .with_uri("icaps://localhost:11344/scan")?
        .with_tls(tls)
        .build();

    let response = client.send(&Request::options("scan")).await?;
    println!("ICAP {} {}", response.status_code().as_u16(), response.status_text());
    Ok(())
}
```

`with_sni` overrides the SNI server name; useful when the certificate is
issued for a DNS name but the client connects to an IP literal or test
endpoint.

Use `add_root_ca_pem_file` when the certificate bundle really is a file path.

### Client mTLS

Present a client certificate and key when the server requires one:

```rust,ignore
use icap_rs::tls::ClientTlsConfig;

let tls = ClientTlsConfig::with_native_roots()
    .add_root_ca_pem_file("test_data/certs/ca.pem")?
    .with_client_auth_pem_files("test_data/certs/client.crt", "test_data/certs/client.key")?
    .with_sni("localhost");
```

### Disabling Certificate Verification

For local testing against self-signed servers, the client can opt into
"no verify" mode, equivalent to `c-icap-client -tls-no-verify`:

```rust,ignore
use icap_rs::tls::ClientTlsConfig;

let tls = ClientTlsConfig::with_native_roots()
    .dangerous_disable_cert_verification()?;
```

This is logged at WARN level whenever it takes effect. The method name
intentionally starts with `dangerous_` so code review can spot it easily.
Never use it in production.

### Handshake Timeout

Both client and server cap TLS handshakes at 10 seconds by default. Override
through `with_handshake_timeout`:

```rust,ignore
use std::time::Duration;
use icap_rs::tls::ClientTlsConfig;

let tls = ClientTlsConfig::with_native_roots()
    .with_handshake_timeout(Duration::from_secs(3));
```

## Server TLS

```rust,ignore
use icap_rs::{IncomingRequest, Response, Server};
use icap_rs::server::options::ServiceOptions;
use icap_rs::tls::ServerTlsConfig;

const ISTAG: &str = "tls-server-1.0";

#[cfg(feature = "tls-rustls")]
#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let cert_pem = std::fs::read_to_string("test_data/certs/server.crt")?;
    let key_pem = std::fs::read_to_string("test_data/certs/server.key")?;
    let tls = ServerTlsConfig::from_pem(cert_pem, key_pem)?;

    let server = Server::builder()
        .bind("0.0.0.0:11344")
        .with_tls(tls)
        .route_respmod(
            "respmod",
            |_request: IncomingRequest| async move {
                Response::no_content_with_istag(ISTAG)
            },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("TLS RESPMOD")
                    .allow_204(),
            ),
        )
        .build()
        .await?;

    server.run().await
}
```

The server terminates TLS inside the Rustls acceptor and then handles ICAP
normally. The certificate loader auto-detects PKCS#8, PKCS#1 (RSA) and SEC1
(EC) private key formats.

Use `ServerTlsConfig::from_pem_files` when the certificate chain and key
really are files on disk.

When the connection limit is exceeded, TLS listeners drop the TCP socket
*before* terminating the handshake; clients that hammer an overloaded server
do not waste server CPU on handshake work.

## Server mTLS

Require clients to present a certificate signed by a trusted CA:

```rust,ignore
use icap_rs::tls::ServerTlsConfig;

let tls = ServerTlsConfig::from_pem_files("certs/server.crt", "certs/server.key")?
    .with_client_auth_pem_file("certs/ca.pem")?;
```

Use `with_client_auth_pem` / `with_optional_client_auth_pem` for PEM content,
or `with_optional_client_auth_pem_file` to request — but not require — a
client certificate with CA roots loaded from a file.

## Bring Your Own `rustls` Config

For advanced cases (HSM-backed keys, custom verifiers, OCSP, custom session
storage, cipher suite control) bypass the PEM-file builders entirely:

```rust,ignore
use std::sync::Arc;
use icap_rs::tls::{ClientTlsConfig, ServerTlsConfig};

let server_cfg: Arc<rustls::ServerConfig> = /* … */ unimplemented!();
let server_tls = ServerTlsConfig::from_rustls_config(server_cfg);

let client_cfg: Arc<rustls::ClientConfig> = /* … */ unimplemented!();
let client_tls = ClientTlsConfig::from_rustls_config(client_cfg);
```

## Structured TLS Errors

TLS failures surface through `Error::Tls(TlsError)` rather than collapsing
into generic `Error::Network` (the previous behavior). This lets callers
distinguish certificate verification problems, handshake timeouts and SNI
errors from ordinary network failures:

```rust,ignore
use icap_rs::error::Error;
use icap_rs::tls::TlsError;

match client.send(&req).await {
    Ok(resp) => { /* … */ }
    Err(Error::Tls(TlsError::HandshakeTimeout(d))) => {
        eprintln!("TLS handshake exceeded {d:?}");
    }
    Err(Error::Tls(TlsError::Handshake(e))) => {
        eprintln!("TLS handshake failed: {e}");
    }
    Err(Error::Tls(other)) => eprintln!("TLS error: {other}"),
    Err(other) => eprintln!("other error: {other}"),
}
```

Note: in TLS 1.3, an `mTLS rejected` outcome can arrive after the client's
handshake has already completed (the server may emit a
`certificate_required` alert post-handshake). Those failures still indicate
a TLS-layer problem but surface through `Error::Network` because they
happen during normal I/O on an already-handshaken connection.

## Benchmarking TLS Overhead

The crate includes a Criterion benchmark that runs the same local RESPMOD
service over plaintext ICAP and direct ICAPS, then compares client round-trip
cost for a `204 No Content` response:

```bash
cargo bench -p icap-rs --bench tls_overhead_bench --features tls-rustls
```

The benchmark uses the test PEM files from `test_data/certs` and reports two
groups:

- `tls_overhead_keepalive`: one warmed connection is reused. This mostly
  shows the per-request overhead of encrypted I/O and Rustls framing after
  the TLS handshake has already happened.
- `tls_overhead_new_connection`: every request opens a new connection. This
  includes TCP connect cost for both transports and additionally includes
  the TLS handshake for ICAPS. The benchmark caps the number of real
  short-lived connections per Criterion sample to avoid measuring loopback
  ephemeral-port exhaustion on platforms such as Windows. Treat this group
  as a coarse handshake-overhead benchmark: it is useful for large
  plain-vs-TLS differences, but not for judging small regressions.

Use the `plain_icap` and `tls_icaps` entries inside each group as the direct
comparison pair. Absolute numbers depend on CPU, OS TCP behavior, certificate
verification cost, and Criterion settings, so the intended signal is the
ratio between those two entries on the same machine.
