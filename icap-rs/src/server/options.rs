//! ICAP OPTIONS configuration.
//!
//! This module provides types to build an ICAP `OPTIONS` response for a given
//! service. It includes:
//! - [`Method`](crate::Method) — ICAP methods
//! - [`TransferBehavior`] — per-extension transfer hints (Preview/Ignore/Complete)
//! - [`ServiceOptions`] — a builder-like struct that serializes to an ICAP response
//!   and supports a dynamic `ISTag` provider.
//!
//! ## Dynamic `ISTag` provider
//! Some deployments need the ICAP `ISTag` to reflect a mutable policy (e.g. a
//! filtering rule-set version). Use [`ServiceOptions::with_istag_provider`] to
//! supply a closure that computes the `ISTag` *per request* (including `OPTIONS`).
//! `ServiceOptions` intentionally has no default `ISTag`; services must provide
//! a static tag or a dynamic provider explicitly.
//!
//! ### Example
//! ```
//! # use icap_rs::server::options::ServiceOptions;
//! # use icap_rs::IncomingRequest;
//! # let state = std::sync::Arc::new(std::sync::Mutex::new(String::from("respmod-1.0")));
//! let opts = ServiceOptions::new()
//!     .with_istag_provider({
//!         let state = state.clone();
//!         move |_: &IncomingRequest| state.lock().unwrap().clone()
//!     })
//!     .with_service("Response Modifier")
//!     .with_options_ttl(60)
//!     .allow_204();
//! ```

use std::sync::{Arc, RwLock};

use crate::error::{Error, IcapResult};
use crate::request::IncomingRequest;
use crate::response::Response;
use std::collections::HashMap;

/// Transfer behavior for file extensions advertised via `Transfer-*` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferBehavior {
    /// Files should be sent with preview.
    Preview,
    /// Files should be ignored.
    Ignore,
    /// Files should be sent fully without preview.
    Complete,
}

/// Source of the `ISTag` value used in responses.
///
/// - `Static`: fixed at configuration time (backward compatible).
/// - `Dynamic`: computed per incoming request via a user-provided closure.
///   This allows the `ISTag` to track a mutable policy or any other runtime state.
#[derive(Clone)]
pub enum IstagSource {
    Static(String),
    Dynamic(Arc<dyn Fn(&IncomingRequest) -> String + Send + Sync>),
}

impl IstagSource {
    /// Resolve the current `ISTag` for the given request.
    #[inline]
    pub fn current_for(&self, req: &IncomingRequest) -> String {
        match self {
            Self::Static(s) => s.clone(),
            Self::Dynamic(f) => (f)(req),
        }
    }
}

/// A cloneable handle to a mutable `ISTag` value.
///
/// Create one with [`IsTagHandle::new`], pass clones to both
/// [`ServiceOptions::with_dynamic_istag`] and your route handlers, then call
/// [`IsTagHandle::set`] from a background task whenever the policy reloads.
///
/// `IsTagHandle::clone` is cheap — it clones the inner `Arc`, not the string.
///
/// # Example
///
/// ```rust,no_run
/// use icap_rs::{IsTagHandle, IncomingRequest, Response, Server, HandlerResult};
/// use icap_rs::server::options::ServiceOptions;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
///     let tag = IsTagHandle::new("policy-v1");
///
///     // Rotate the tag from a background task on policy reload.
///     tokio::spawn({
///         let tag = tag.clone();
///         async move {
///             loop {
///                 tokio::time::sleep(Duration::from_secs(60)).await;
///                 tag.set("policy-v2");
///             }
///         }
///     });
///
///     let server = Server::builder()
///         .bind("127.0.0.1:1344")
///         .route_reqmod(
///             "scan",
///             move |req: IncomingRequest| {
///                 // req.istag() returns the tag resolved before the handler was called.
///                 async move { Ok(Response::no_content_with_istag(req.istag().unwrap_or(""))?) }
///             },
///             Some(ServiceOptions::new()
///                 .with_dynamic_istag(tag)
///                 .with_service("Scanner")
///                 .allow_204()),
///         )
///         .build()
///         .await?;
///
///     server.run().await?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct IsTagHandle(Arc<RwLock<String>>);

impl IsTagHandle {
    /// Create a new handle with the given initial tag value.
    pub fn new(initial: impl Into<String>) -> Self {
        Self(Arc::new(RwLock::new(initial.into())))
    }

    /// Replace the current tag value.
    ///
    /// All `ServiceOptions` and handlers that share this handle will see the
    /// new value on their next request.
    pub fn set(&self, tag: impl Into<String>) {
        *self.0.write().expect("IsTagHandle lock poisoned") = tag.into();
    }

    /// Read the current tag value.
    pub fn current(&self) -> String {
        self.0.read().expect("IsTagHandle lock poisoned").clone()
    }
}

impl From<IsTagHandle> for IstagSource {
    fn from(h: IsTagHandle) -> Self {
        Self::Dynamic(Arc::new(move |_: &IncomingRequest| h.current()))
    }
}

/// Configuration for generating an ICAP `OPTIONS` response.
#[derive(Clone)]
#[must_use]
pub struct ServiceOptions {
    /// Human-readable service description (optional).
    pub(crate) service: Option<String>,
    /// `ISTag` source (static or dynamic provider).
    pub(crate) istag: Option<IstagSource>,
    /// Max concurrent connections hint (optional).
    pub(crate) max_connections: Option<usize>,
    /// TTL (seconds) for caching the OPTIONS response (optional).
    pub(crate) options_ttl: Option<u32>,
    /// Short service identifier (optional).
    pub(crate) service_id: Option<String>,
    /// Capabilities advertised in `Allow` (optional), e.g. `"204"`.
    pub(crate) allow: Vec<String>,
    /// `Preview` size in bytes (optional).
    pub(crate) preview: Option<u32>,
    /// Per-extension transfer behavior (`Transfer-*` headers).
    pub(crate) transfer_rules: HashMap<String, TransferBehavior>,
    /// Default transfer behavior applied when an extension is not matched.
    pub(crate) default_transfer_behavior: Option<TransferBehavior>,
    /// Extra custom headers to include as `Header: Value`.
    pub(crate) custom_headers: HashMap<String, String>,
    /// `Opt-body-type` (if `opt-body` is present).
    pub(crate) opt_body_type: Option<String>,
    /// Optional message body to advertise via `Encapsulated: opt-body=0`.
    pub(crate) opt_body: Option<Vec<u8>>,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceOptions {
    /// Create a new OPTIONS config without an `ISTag`.
    ///
    /// ICAP success responses require an explicit `ISTag`. Call
    /// [`with_static_istag`](Self::with_static_istag) or
    /// [`with_istag_provider`](Self::with_istag_provider) before registering
    /// this config on a server route.
    pub fn new() -> Self {
        Self {
            service: None,
            istag: None,
            max_connections: None,
            options_ttl: None,
            service_id: None,
            allow: Vec::new(),
            preview: None,
            transfer_rules: HashMap::new(),
            default_transfer_behavior: None,
            custom_headers: HashMap::new(),
            opt_body_type: None,
            opt_body: None,
        }
    }

    /// Provide a **dynamic `ISTag` provider** that will be invoked for **each request**
    /// (including `OPTIONS`). The closure should be fast and lock-free if possible.
    ///
    /// The provider returns the logical tag value. It may return a raw token
    /// such as `policy-1` or a base64-like value such as `QUJD+/8=`; generated
    /// ICAP responses quote the value on the wire per RFC 3507.
    ///
    /// Typical sources include: a version string stored in an `Arc<RwLock<String>>`,
    /// an atomic epoch counter, or a lightweight in-process cache.
    ///
    /// # Example
    /// ```
    /// # use std::sync::{Arc, RwLock};
    /// # use icap_rs::server::options::ServiceOptions;
    /// # use icap_rs::IncomingRequest;
    /// let tag = Arc::new(RwLock::new(String::from("respmod-1.0")));
    /// let opts = ServiceOptions::new()
    ///     .with_istag_provider({
    ///         let tag = tag.clone();
    ///         move |_: &IncomingRequest| tag.read().unwrap().clone()
    ///     });
    /// ```
    pub fn with_istag_provider<F>(mut self, f: F) -> Self
    where
        F: Fn(&IncomingRequest) -> String + Send + Sync + 'static,
    {
        self.istag = Some(IstagSource::Dynamic(Arc::new(f)));
        self
    }

    /// Use a **static** `ISTag` for responses.
    ///
    /// The value may be passed as a raw token such as `policy-1` or
    /// `QUJD+/8=`. Generated ICAP responses quote it on the wire per RFC 3507.
    pub fn with_static_istag(mut self, istag: &str) -> Self {
        self.istag = Some(IstagSource::Static(istag.to_string()));
        self
    }

    /// Use an [`IsTagHandle`] as the `ISTag` source.
    ///
    /// This is the preferred way to wire up a dynamically-rotating tag.
    /// The handle can be shared with route handlers via `Clone`; call
    /// [`IsTagHandle::set`] from anywhere to rotate the tag atomically.
    pub fn with_dynamic_istag(mut self, handle: IsTagHandle) -> Self {
        self.istag = Some(handle.into());
        self
    }

    /// Set the human-readable service description.
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    /// Router-only: set Max-Connections from global advertised limit if not set.
    pub(crate) const fn with_max_connections(&mut self, n: usize) {
        self.max_connections = Some(n);
    }

    /// Set `Options-TTL` (seconds).
    pub const fn with_options_ttl(mut self, ttl: u32) -> Self {
        self.options_ttl = Some(ttl);
        self
    }

    /// Set short service ID.
    pub fn with_service_id(mut self, service_id: &str) -> Self {
        self.service_id = Some(service_id.to_string());
        self
    }

    /// Add a capability to `Allow` (e.g. `"204"`).
    pub fn add_allow(mut self, capability: &str) -> Self {
        self.allow.push(capability.to_string());
        self
    }

    /// Advertise support for `204 No Content` no-modification responses.
    ///
    /// This is equivalent to `add_allow("204")`, but avoids stringly typed
    /// capability values in normal service configuration.
    pub fn allow_204(self) -> Self {
        self.add_allow_once("204")
    }

    /// Advertise support for `206 Partial Content` no-modification responses.
    ///
    /// This is equivalent to `add_allow("206")`, but avoids stringly typed
    /// capability values in normal service configuration.
    pub fn allow_206(self) -> Self {
        self.add_allow_once("206")
    }

    /// Set Preview size (bytes).
    pub const fn with_preview(mut self, preview: u32) -> Self {
        self.preview = Some(preview);
        self
    }

    /// Add rule for a file extension (e.g. "pdf", "exe").
    pub fn add_transfer_rule(mut self, extension: &str, behavior: TransferBehavior) -> Self {
        self.transfer_rules.insert(extension.to_string(), behavior);
        self
    }

    /// Set default transfer behavior (applied when an extension is not matched).
    pub const fn with_default_transfer_behavior(mut self, behavior: TransferBehavior) -> Self {
        self.default_transfer_behavior = Some(behavior);
        self
    }

    /// Add a custom header.
    pub fn add_custom_header(mut self, name: &str, value: &str) -> Self {
        self.custom_headers
            .insert(name.to_string(), value.to_string());
        self
    }

    /// Advertise an opt-body in the service's `OPTIONS` response (RFC 3507 §4.10).
    ///
    /// The generated `OPTIONS` response sets `Encapsulated: opt-body=0`, adds an
    /// `Opt-body-type: <body_type>` header, and serializes `body` as a single
    /// ICAP chunk terminated by `0\r\n\r\n`. `body_type` describes the payload
    /// (for example `"text/plain"` or a service-defined token); it is required
    /// whenever an opt-body is present and is checked by
    /// [`ServiceOptions::validate`] at server build time.
    ///
    /// A client reading the `OPTIONS` response receives the dechunked bytes via
    /// `Response::body()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use icap_rs::server::options::ServiceOptions;
    ///
    /// let options = ServiceOptions::new()
    ///     .with_static_istag("opt-1.0")
    ///     .with_service("Scanner")
    ///     .with_opt_body("text/plain", b"server info".to_vec());
    /// ```
    pub fn with_opt_body(mut self, body_type: &str, body: Vec<u8>) -> Self {
        self.opt_body_type = Some(body_type.to_string());
        self.opt_body = Some(body);
        self
    }

    /// Resolve the `ISTag` for a specific request (static or dynamic).
    #[inline]
    pub(crate) fn istag_for(&self, req: &IncomingRequest) -> IcapResult<String> {
        self.istag
            .as_ref()
            .map(|source| source.current_for(req))
            .ok_or_else(|| Error::missing_header("ISTag"))
    }

    /// Validate invariants for this configuration.
    ///
    /// For dynamic `ISTag` providers it is not possible to validate non-emptiness
    /// at configuration time; perform validation when computing the value if needed.
    pub fn validate(&self) -> Result<(), String> {
        if self.istag.is_none() {
            return Err(
                "ISTag must be configured explicitly with with_static_istag or with_istag_provider"
                    .to_string(),
            );
        }
        if !self.transfer_rules.is_empty() && self.default_transfer_behavior.is_none() {
            return Err(
                "Default transfer behavior must be set when transfer rules are defined".to_string(),
            );
        }
        if self.opt_body.is_some() && self.opt_body_type.is_none() {
            return Err("Opt-body-type must be set when opt-body is present".to_string());
        }
        Ok(())
    }

    fn add_allow_once(mut self, capability: &str) -> Self {
        if !self.allow.iter().any(|c| c == capability) {
            self.allow.push(capability.to_string());
        }
        self
    }
}

/// Assembles an ICAP `OPTIONS` response from a [`ServiceOptions`] config and
/// the set of methods the router registered for the service.
///
/// Kept `pub(crate)` — callers outside this crate interact only with
/// [`ServiceOptions`] and never need to construct a response directly.
pub(crate) struct OptionsResponseBuilder<'a> {
    options: &'a ServiceOptions,
    methods_str: &'a str,
}

impl<'a> OptionsResponseBuilder<'a> {
    pub(crate) const fn new(options: &'a ServiceOptions, methods_str: &'a str) -> Self {
        Self {
            options,
            methods_str,
        }
    }

    /// Build the `OPTIONS` response for the given incoming request.
    pub(crate) fn build(self, req: &IncomingRequest) -> IcapResult<Response> {
        let istag_now = self.options.istag_for(req)?;
        let mut response = Response::ok_with_istag(&istag_now)?;

        response = response.add_header("Methods", self.methods_str);

        let encapsulated_value = if self.options.opt_body.is_some() {
            "opt-body=0"
        } else {
            "null-body=0"
        };
        response = response.add_header("Encapsulated", encapsulated_value);

        if let Some(ref service) = self.options.service {
            response = response.add_header("Service", service);
        }
        if let Some(max_conn) = self.options.max_connections {
            response = response.add_header("Max-Connections", &max_conn.to_string());
        }
        if let Some(ttl) = self.options.options_ttl {
            response = response.add_header("Options-TTL", &ttl.to_string());
        }
        if let Some(ref service_id) = self.options.service_id {
            response = response.add_header("Service-ID", service_id);
        }
        if !self.options.allow.is_empty() {
            response = response.add_header("Allow", &self.options.allow.join(", "));
        }
        if let Some(preview) = self.options.preview {
            response = response.add_header("Preview", &preview.to_string());
        }
        if let Some(ref opt_body_type) = self.options.opt_body_type {
            response = response.add_header("Opt-body-type", opt_body_type);
        }

        // Transfer-* headers
        if !self.options.transfer_rules.is_empty() {
            let mut preview_extensions = Vec::new();
            let mut ignore_extensions = Vec::new();
            let mut complete_extensions = Vec::new();

            for (ext, behavior) in &self.options.transfer_rules {
                match behavior {
                    TransferBehavior::Preview => preview_extensions.push(ext.clone()),
                    TransferBehavior::Ignore => ignore_extensions.push(ext.clone()),
                    TransferBehavior::Complete => complete_extensions.push(ext.clone()),
                }
            }
            if let Some(ref default_behavior) = self.options.default_transfer_behavior {
                match default_behavior {
                    TransferBehavior::Preview => preview_extensions.push("*".into()),
                    TransferBehavior::Ignore => ignore_extensions.push("*".into()),
                    TransferBehavior::Complete => complete_extensions.push("*".into()),
                }
            }
            if !preview_extensions.is_empty() {
                response = response.add_header("Transfer-Preview", &preview_extensions.join(", "));
            }
            if !ignore_extensions.is_empty() {
                response = response.add_header("Transfer-Ignore", &ignore_extensions.join(", "));
            }
            if !complete_extensions.is_empty() {
                response =
                    response.add_header("Transfer-Complete", &complete_extensions.join(", "));
            }
        }

        for (name, value) in &self.options.custom_headers {
            response = response.add_header(name, value);
        }
        if let Some(ref opt_body) = self.options.opt_body {
            response = response.with_body(opt_body);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_allow_helpers_advertise_no_modification_capabilities() {
        let opts = ServiceOptions::new().allow_204().allow_206();

        assert_eq!(opts.allow, ["204", "206"]);
    }

    #[test]
    fn typed_allow_helpers_do_not_duplicate_capabilities() {
        let opts = ServiceOptions::new()
            .allow_204()
            .allow_204()
            .allow_206()
            .allow_206();

        assert_eq!(opts.allow, ["204", "206"]);
    }
}
