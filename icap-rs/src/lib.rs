#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

pub mod client;
pub mod error;
mod net;
mod protocol;
pub mod request;
pub mod response;
pub mod server;
#[cfg(feature = "tls-rustls")]
pub mod tls;

pub use client::Client;
pub use client::builder::*;
pub use client::timeouts::ClientTimeouts;
pub use error::{Error, IcapResult};
pub use request::{
    Body, EmbeddedHttp, EmbeddedHttpKind, Incoming, IncomingRequest, Method, Outbound,
    OutboundRequest, Request,
};
pub use response::{Outgoing, OutgoingResponse, Parsed, ParsedResponse, Response, StatusCode};
pub use server::{
    BoxError, HandlerError, HandlerResult, IsTagHandle, PreviewDecision, RouteOutput, Server,
    ServerBuilder, ServerTimeouts, ServiceOptions, TransferBehavior,
};
#[cfg(feature = "tls-rustls")]
pub use tls::{ClientTlsConfig, ServerTlsConfig, TlsError};

/// Lib version.
pub const LIB_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Max Header size.
pub const MAX_HDR_BYTES: usize = 64 * 1024;
/// Supported ICAP protocol version.
pub const ICAP_VERSION: &str = "ICAP/1.0";
