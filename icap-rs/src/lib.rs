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
pub use client::builder::{ClientBuilder, ConnectionPolicy, ProxyAuth};
pub use client::options_cache::OptionsCacheConfig;
pub use client::timeouts::ClientTimeouts;
pub use error::{Error, IcapResult};
pub use request::{
    Body, DirectionMeta, EmbeddedHttp, EmbeddedHttpKind, Incoming, IncomingRequest, Method,
    Outbound, OutboundRequest, Request,
};
pub use response::{Outgoing, OutgoingResponse, Parsed, ParsedResponse, Response, StatusCode};
pub use server::{
    BoxError, HandlerError, HandlerResult, IsTagHandle, PreviewDecision, RouteOutput, Server,
    ServerBuilder, ServerTimeouts, ServiceOptions, ShutdownEvent, TransferBehavior,
};
#[cfg(feature = "tls-rustls")]
pub use tls::{ClientTlsConfig, ServerTlsConfig, TlsError};

/// Lib version.
pub const LIB_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Supported ICAP protocol version.
pub const ICAP_VERSION: &str = "ICAP/1.0";

pub(crate) const DEFAULT_ICAP_HEADER_BYTES: usize = 64 * 1024;
