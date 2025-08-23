//! # icap-rs
//!
//! A Rust implementation of the **ICAP** protocol ([RFC 3507]) focused on a
//! practical, ergonomic client API and server.
//!
//! [RFC 3507]: https://www.rfc-editor.org/rfc/rfc3507
//!
//! ## Status
//! **Work in progress.**
//!
//! The **client** (`icap_rs::Client`) is functional and can:
//! - Build and send ICAP requests (`OPTIONS`, `REQMOD`, `RESPMOD`).
//! - Negotiate capabilities (e.g. `Preview`, `Allow: 204/206`, methods, timeout).
//! - Embed HTTP/1.x requests and responses inside ICAP messages.
//! - Stream large bodies from file or memory (with `Preview: 0` or negotiated preview).
//! - Inspect the raw ICAP wire format (similar to `c-icap-client`).
//!
//! The **server** module exists and supports basic per-service routing and proper
//! draining of ICAP-chunked bodies, but it is **not production-ready** yet and
//! its APIs may change.
//!
//! ## Design notes
//! - The client keeps **transport** details (`host:port`, timeouts, keep-alive).
//! - The `Request` carries **semantics**, including the **service path**
//!   (e.g. `reqmod`, `respmod`, `icap/test`). This mirrors common ICAP client
//!   designs and keeps the API predictable.
//! - Preview handling includes `0; ieof` fast-204 hints via `Request::preview_ieof(true)`.
//!
//! ## Modules
//! - [`client`] — ICAP client implementation (main working component).
//! - [`error`] — common error types (`IcapError`, `IcapResult`).
//! - [`options`] — helpers for building `OPTIONS` responses (`OptionsConfig`, `TransferBehavior`).
//! - [`request`] — ICAP request type and helpers (`Request`, `EmbeddedHttp`).
//! - [`response`] — ICAP response model and builder (`Response`, `ResponseBuilder`, `StatusCode`).
//! - [`server`] — minimal ICAP server abstractions (`Server`, `ServerBuilder`, `RequestHandler`).
//!
//! ## Quick start: Client
//! ```no_run
//! use icap_rs::{Client, Request};
//!
//! #[tokio::main]
//! async fn main() -> icap_rs::error::IcapResult<()> {
//!     // Transport: where to connect
//!     let client = Client::builder()
//!         .from_uri("icap://127.0.0.1:1344")?
//!         .keep_alive(true)
//!         .build();
//!
//!     // Semantics: which ICAP service to call
//!     let req = Request::options("/respmod");
//!
//!     let resp = client.send(&req).await?;
//!     println!("ICAP: {} {}", resp.status_code, resp.status_text);
//!     Ok(())
//! }
//! ```
//!
//! ## Example: Server
//! A minimal server that exposes two services (`reqmod`, `respmod`) and replies `204 No Content`.
//! ```no_run
//! use icap_rs::{
//!     error::IcapResult, IcapMethod, OptionsConfig, Response, Server, ServerBuilder, StatusCode
//! };
//!
//! #[tokio::main]
//! async fn main() -> IcapResult<()> {
//!     let server = Server::builder()
//!         .bind("127.0.0.1:1344")
//!         // REQMOD → 204 (no modification)
//!         .add_service("reqmod", |_req| async move {
//!             Ok(Response::new(StatusCode::NoContent204, "No Modifications")
//!                 .add_header("Content-Length", "0"))
//!         })
//!         // RESPMOD → 204 (no modification)
//!         .add_service("respmod", |_req| async move {
//!             Ok(Response::new(StatusCode::NoContent204, "No Modifications")
//!                 .add_header("Content-Length", "0"))
//!         })
//!         // OPTIONS for each service
//!         .add_options_config(
//!             "reqmod",
//!             OptionsConfig::new(vec![IcapMethod::ReqMod], "example-reqmod-1.0")
//!                 .with_service("Example REQMOD Service")
//!                 .with_options_ttl(600)
//!                 .add_allow("204"),
//!         )
//!         .add_options_config(
//!             "respmod",
//!             OptionsConfig::new(vec![IcapMethod::RespMod], "example-respmod-1.0")
//!                 .with_service("Example RESPMOD Service")
//!                 .with_options_ttl(600)
//!                 .add_allow("204"),
//!         )
//!         .build()
//!         .await?;
//!
//!     server.run().await
//! }
//! ```
//!
//! ## Testing with an embedded HTTP request
//! ```no_run
//! use http::Request as HttpRequest;
//! use icap_rs::{Client, Request};
//!
//! #[tokio::main]
//! async fn main() -> icap_rs::error::IcapResult<()> {
//!     let http_req = HttpRequest::builder()
//!         .method("GET")
//!         .uri("http://example.com/")
//!         .header("Host", "example.com")
//!         .body(Vec::<u8>::new())
//!         .unwrap();
//!
//!     let client = Client::builder().from_uri("icap://127.0.0.1:1344")?.build();
//!     let icap_req = Request::reqmod("reqmod")
//!         .allow_204(true)
//!         .preview(4)
//!         .with_http_request(http_req);
//!
//!     let resp = client.send(&icap_req).await?;
//!     println!("ICAP: {} {}", resp.status_code, resp.status_text);
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod options;
mod parser;
pub mod request;
pub mod response;
pub mod server;

pub use client::Client;
pub use options::{IcapMethod, IcapOptionsBuilder, OptionsConfig, TransferBehavior};
pub use request::{EmbeddedHttp, Request};
pub use response::{Response, ResponseBuilder, StatusCode};
pub use server::{RequestHandler, Server, ServerBuilder};

///Lib version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
///Max Header size
pub const MAX_HDR_BYTES: usize = 64 * 1024;
