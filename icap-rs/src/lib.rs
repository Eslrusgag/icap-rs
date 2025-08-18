///crate in development!!
pub mod client;
pub mod error;
pub mod http;
pub mod options;
mod parser;
pub mod request;
pub mod response;
pub mod server;

pub use client::Client;

pub use server::{RequestHandler, Server, ServerBuilder};

pub use http::{HttpMessage, HttpMessageBuilder, HttpMessageTrait, HttpSession};
pub use options::{IcapMethod, IcapOptionsBuilder, OptionsConfig, TransferBehavior};
pub use parser::*;
pub use request::Request;
pub use response::{Response, ResponseBuilder, StatusCode};
