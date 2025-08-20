//! # icap-rs
//!
//! ICAP (RFC 3507) implementation in Rust**.
//!
//! ## Status
//! **Work in progress.**
//! Currently, the client side (`icap_rs::Client`) is functional and can:
//! - Build and send ICAP requests (`OPTIONS`, `REQMOD`, `RESPMOD`).
//! - Negotiate capabilities (`Preview`, `Allow: 204`, methods, timeout).
//! - Embed HTTP/1.x requests and responses inside ICAP messages.
//! - Stream body data from file or memory (with `Preview: 0` or negotiated preview).
//! - Print raw ICAP wire messages (c-icap-client style).
//!
//! The server module exists, but is not yet production-ready.
//!
//! ## Exposed modules
//! - [`client`] — ICAP client implementation (main working component).
//! - [`error`] — common error types (`IcapError`, `IcapResult`).
//! - [`options`] — OPTIONS request/response helpers (`IcapOptionsBuilder`, `TransferBehavior`).
//! - [`request`] — ICAP request builder (`Request`).
//! - [`response`] — ICAP response model (`Response`, `ResponseBuilder`, `StatusCode`).
//! - [`server`] — early draft of ICAP server abstractions (`Server`, `ServerBuilder`, `RequestHandler`).
//! ## Example
//! ```no_run
//! use icap_rs::{Client, Request};
//!
//! #[tokio::main]
//! async fn main() -> icap_rs::error::IcapResult<()> {
//!     let client = Client::builder()
//!         .from_uri("icap://127.0.0.1:1344/respmod")?
//!         .build();
//!
//!     let req = Request::options("/respmod");
//!     let resp = client.send(&req).await?;
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
pub use parser::*;
pub use request::{EmbeddedHttp, Request};
pub use response::{Response, ResponseBuilder, StatusCode};
pub use server::{RequestHandler, Server, ServerBuilder};
