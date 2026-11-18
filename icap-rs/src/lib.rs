#![cfg_attr(
    feature = "full",
    doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
)]
#![cfg_attr(
    not(feature = "full"),
    doc = "Bounded ICAP transactions over caller-owned transports and buffers. See [`streaming`]. Enable the default `full` feature for the convenience client/server API."
)]

#[cfg(feature = "full")]
pub mod client;
#[cfg(feature = "full")]
pub mod error;
#[cfg(feature = "full")]
mod net;
#[cfg(feature = "full")]
mod protocol;
#[cfg(feature = "full")]
pub mod request;
#[cfg(feature = "full")]
pub mod response;
#[cfg(feature = "full")]
pub mod server;
pub mod streaming;
#[cfg(feature = "tls-rustls")]
pub mod tls;

#[cfg(feature = "full")]
pub use client::Client;
#[cfg(feature = "full")]
pub use client::builder::{ClientBuilder, ConnectionPolicy, ProxyAuth};
#[cfg(feature = "full")]
pub use client::options_cache::OptionsCacheConfig;
#[cfg(feature = "full")]
pub use client::timeouts::ClientTimeouts;
#[cfg(feature = "full")]
pub use error::{Error, IcapResult};
#[cfg(feature = "full")]
pub use request::{
    Body, DirectionMeta, EmbeddedHttp, EmbeddedHttpKind, Incoming, IncomingRequest, Method,
    Outbound, OutboundRequest, Request,
};
#[cfg(feature = "full")]
pub use response::{Outgoing, OutgoingResponse, Parsed, ParsedResponse, Response, StatusCode};
#[cfg(feature = "full")]
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

#[cfg(feature = "full")]
pub(crate) const DEFAULT_ICAP_HEADER_BYTES: usize = 64 * 1024;
