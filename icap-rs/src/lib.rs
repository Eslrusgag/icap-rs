///crate in development!!
pub mod client;
pub mod error;
pub mod http;
pub mod icap_request;
pub mod icap_response;
pub mod options;
pub mod parser;
pub mod server;

pub use client::{IcapClient, IcapClientBuilder};

pub use server::{IcapRequestHandler, IcapServer, IcapServerBuilder};

pub use http::{HttpMessage, HttpMessageBuilder, HttpMessageTrait, HttpSession};
pub use icap_request::IcapRequest;
pub use icap_response::{IcapResponse, IcapResponseBuilder, IcapStatusCode};
pub use options::{IcapMethod, IcapOptionsBuilder, IcapOptionsConfig, TransferBehavior};
pub use parser::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
