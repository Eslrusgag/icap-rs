# TLS (ICAPS)

`icap-rs` supports **ICAPS (ICAP over TLS)** via **rustls** (ring) behind a cargo feature.

> If you use icaps://… URI but build without tls-rustls feature, the client will throw an error.

---

## Cargo features

```toml
icap-rs = { version = "0.1.0", features = "tls-rustls" }
```

---

## Client (ICAPS)

```rust,no_run
use icap_rs::{Client, Request};

#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let client = Client::builder()
        .with_uri("icaps://icap.example:11344")?
        .build();

    let req = Request::options("respmod");
    let resp = client.send(&req).await?;
    println!("ICAP: {} {}", resp.status_code.as_str(), resp.status_text);
    Ok(())
}
```

### Notes & limitations (client)

- Certificate verification cannot be disabled via public rustls APIs.
- Client authentication (mTLS) is not implemented yet.
- Default ICAPS port is **11344** if not specified explicitly.

---

## Server (ICAPS)

```rust,no_run
#[cfg(feature = "tls-rustls")]
use icap_rs::{Server, Request, Response};
#[cfg(feature = "tls-rustls")]
use icap_rs::server::options::ServiceOptions;

#[cfg(feature = "tls-rustls")]
const ISTAG: &str = "scan-1.0";

#[cfg(feature = "tls-rustls")]
#[tokio::main]
async fn main() -> icap_rs::error::IcapResult<()> {
    let server = Server::builder()
        .bind("0.0.0.0:13443")
        .with_tls_from_pem_files(
            "test_data/certs/server.crt",
            "test_data/certs/server.key",
        )
        .route("scan", [icap_rs::Method::ReqMod, icap_rs::Method::RespMod],
            |_req: Request| async move {
                Ok(Response::no_content().try_set_istag(ISTAG)?)
            },
            Some(ServiceOptions::new().with_static_istag(ISTAG).add_allow("204")),
        )
        .build()
        .await?;

    server.run().await
}

#[cfg(not(feature = "tls-rustls"))]
fn main() {}
```
