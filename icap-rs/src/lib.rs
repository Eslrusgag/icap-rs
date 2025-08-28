#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

pub mod client;
pub mod error;
mod parser;
pub mod request;
pub mod response;
pub mod server;

pub use client::Client;
pub use request::{EmbeddedHttp, Method, Request};
pub use response::{Response, StatusCode};
pub use server::{RequestHandler, Server, ServerBuilder, ServiceOptions, TransferBehavior};

///Lib version
pub const LIB_VERSION: &str = env!("CARGO_PKG_VERSION");
///Max Header size
pub const MAX_HDR_BYTES: usize = 64 * 1024;
/// Supported ICAP protocol version.
pub const ICAP_VERSION: &str = "ICAP/1.0";
