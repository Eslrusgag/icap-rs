# TLS and ICAPS

`icap-rs` supports direct ICAP over TLS (`icaps://`) through Rustls when the
`tls-rustls` feature is enabled.

This is not the RFC 3507 `Upgrade` handshake. Upgrade-based TLS negotiation is
currently unsupported; use direct `icaps://` listeners and clients instead.

## Cargo Feature

```toml
icap-rs = { version = "0.2.0", features = ["tls-rustls"] }
```

The feature enables:

- client-side `icaps://` connections;
- Rustls-backed server listeners;
- server-side mTLS;
- loading extra client trust roots from PEM files.

Without `tls-rustls`, using an `icaps://` URI returns an error.

## Client ICAPS

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icaps://icap.example:11344/respmod")?
        .build();

    let response = client.send(&Request::options("respmod")).await?;
    println!("ICAP {} {}", response.status_code, response.status_text);
    Ok(())
}
```

If no port is present in an `icaps://` URI, the client uses `11344`. Plain
`icap://` still defaults to `1344`.

### Custom CA Bundle

Use `ClientBuilder::add_root_ca_pem_file` when testing with a private CA or
self-signed deployment certificate:

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icaps://localhost:11344/scan")?
        .add_root_ca_pem_file("test_data/certs/ca.crt")?
        .sni_hostname("localhost")
        .build();

    let response = client.send(&Request::options("scan")).await?;
    println!("ICAP {} {}", response.status_code, response.status_text);
    Ok(())
}
```

`sni_hostname` overrides the TLS server name used for SNI and certificate
verification. It is useful when connecting to an IP address or test endpoint
whose certificate is issued for a DNS name.

### Verification Cannot Be Disabled

Rustls 0.23 does not expose a safe public API for disabling certificate
verification. `ClientBuilder::insecure_no_verify` and the CLI `--insecure`
flag are compatibility no-ops and should not be used as a production strategy.
Install a trusted CA or provide one with `add_root_ca_pem_file`.

## Server TLS

```rust,no_run
use icap_rs::{Request, Response, Server};
use icap_rs::server::options::ServiceOptions;

const ISTAG: &str = "tls-server-1.0";

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let server = Server::builder()
        .bind("0.0.0.0:11344")
        .with_tls_from_pem_files(
            "test_data/certs/server.crt",
            "test_data/certs/server.key",
        )
        .route_respmod(
            "respmod",
            |_request: Request| async move {
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
normally. Certificates and private keys are loaded from PEM files. PKCS#8 and
RSA private keys are supported by the loader.

## Server mTLS

Use `with_mtls_from_pem_files` when clients must present certificates signed by
a configured CA:

```rust,no_run
use icap_rs::{Request, Response, Server};
use icap_rs::server::options::ServiceOptions;

const ISTAG: &str = "mtls-server-1.0";

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let server = Server::builder()
        .bind("0.0.0.0:11344")
        .with_mtls_from_pem_files(
            "test_data/certs/server.crt",
            "test_data/certs/server.key",
            "test_data/certs/ca.crt",
        )
        .route_reqmod(
            "scan",
            |_request: Request| async move {
                Response::no_content_with_istag(ISTAG)
            },
            Some(
                ServiceOptions::new()
                    .with_static_istag(ISTAG)
                    .with_service("mTLS REQMOD")
                    .allow_204(),
            ),
        )
        .build()
        .await?;

    server.run().await
}
```
