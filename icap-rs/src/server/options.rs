//! ICAP OPTIONS configuration (WIP).
//!
//! This module provides types to build an ICAP `OPTIONS` response for a given
//! service. It includes:
//! - [`Method`] — ICAP methods
//! - [`TransferBehavior`] — per-extension transfer hints (Preview/Ignore/Complete)
//! - [`ServiceOptions`] — a builder-like struct that serializes to an ICAP response
//!   and supports a dynamic ISTag provider.
//!
//! ## Dynamic ISTag provider
//! Some deployments need the ICAP ISTag to reflect a mutable policy (e.g. a
//! filtering rule-set version). Use [`ServiceOptions::with_istag_provider`] to
//! supply a closure that computes the ISTag *per request* (including `OPTIONS`).
//!
//! ### Example
//! ```no_run
//! # use icap_rs::server::options::ServiceOptions;
//! # use icap_rs::request::Request;
//! # let state = std::sync::Arc::new(std::sync::Mutex::new(String::from("respmod-1.0")));
//! let opts = ServiceOptions::new()
//!     .with_istag_provider({
//!         let state = state.clone();
//!         move |_: &Request| state.lock().unwrap().clone()
//!     })
//!     .with_service("Response Modifier")
//!     .with_options_ttl(60)
//!     .add_allow("204");
//! ```

use std::sync::Arc;

use crate::request::{Method, Request};
use crate::response::{Response, StatusCode};
use smallvec::SmallVec;
use std::collections::HashMap;

/// Transfer behavior for file extensions advertised via `Transfer-*` headers.
#[derive(Debug, Clone, PartialEq)]
pub enum TransferBehavior {
    /// Files should be sent with preview.
    Preview,
    /// Files should be ignored.
    Ignore,
    /// Files should be sent fully without preview.
    Complete,
}

/// Source of the ISTag value used in responses.
///
/// - `Static`: fixed at configuration time (backward compatible).
/// - `Dynamic`: computed per incoming request via a user-provided closure.
///   This allows the ISTag to track a mutable policy or any other runtime state.
#[derive(Clone)]
pub enum IstagSource {
    Static(String),
    Dynamic(Arc<dyn Fn(&Request) -> String + Send + Sync>),
}

impl IstagSource {
    /// Resolve the current ISTag for the given request.
    #[inline]
    pub fn current_for(&self, req: &Request) -> String {
        match self {
            IstagSource::Static(s) => s.clone(),
            IstagSource::Dynamic(f) => (f)(req),
        }
    }
}

/// Configuration for generating an ICAP `OPTIONS` response.
#[derive(Clone)]
pub struct ServiceOptions {
    /// Supported ICAP methods (injected by the router).
    pub(crate) methods: SmallVec<Method, 2>,
    /// Human-readable service description (optional).
    pub service: Option<String>,
    /// ISTag source (static or dynamic provider).
    pub istag: IstagSource,
    /// Max concurrent connections hint (optional).
    pub max_connections: Option<usize>,
    /// TTL (seconds) for caching the OPTIONS response (optional).
    pub options_ttl: Option<u32>,

    /// Short service identifier (optional).
    pub service_id: Option<String>,
    /// Capabilities advertised in `Allow` (optional), e.g. `"204"`.
    pub allow: Vec<String>,
    /// `Preview` size in bytes (optional).
    pub preview: Option<u32>,
    /// Per-extension transfer behavior (`Transfer-*` headers).
    pub transfer_rules: HashMap<String, TransferBehavior>,
    /// Default transfer behavior applied when an extension is not matched.
    pub default_transfer_behavior: Option<TransferBehavior>,
    /// Extra custom headers to include as `Header: Value`.
    pub custom_headers: HashMap<String, String>,
    /// `Opt-body-type` (if `opt-body` is present).
    pub opt_body_type: Option<String>,
    /// Optional message body to advertise via `Encapsulated: opt-body=0`.
    pub opt_body: Option<Vec<u8>>,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceOptions {
    /// Create a new OPTIONS config with required fields.
    ///
    /// This uses a **static** ISTag by default. To make ISTag dynamic, call
    /// [`with_istag_provider`](Self::with_istag_provider).
    pub fn new() -> Self {
        Self {
            methods: SmallVec::new(),
            service: None,
            istag: IstagSource::Static("default".to_string()),
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

    /// Provide a **dynamic ISTag provider** that will be invoked for **each request**
    /// (including `OPTIONS`). The closure should be fast and lock-free if possible.
    ///
    /// Typical sources include: a version string stored in an `Arc<RwLock<String>>`,
    /// an atomic epoch counter, or a lightweight in-process cache.
    ///
    /// # Example
    /// ```
    /// # use std::sync::{Arc, RwLock};
    /// # use icap_rs::server::options::ServiceOptions;
    /// # use icap_rs::request::Request;
    /// let tag = Arc::new(RwLock::new(String::from("respmod-1.0")));
    /// let opts = ServiceOptions::new()
    ///     .with_istag_provider({
    ///         let tag = tag.clone();
    ///         move |_: &Request| tag.read().unwrap().clone()
    ///     });
    /// ```
    pub fn with_istag_provider<F>(mut self, f: F) -> Self
    where
        F: Fn(&Request) -> String + Send + Sync + 'static,
    {
        self.istag = IstagSource::Dynamic(Arc::new(f));
        self
    }

    /// Use a **static** ISTag for responses.
    pub fn with_static_istag(mut self, istag: &str) -> Self {
        self.istag = IstagSource::Static(istag.to_string());
        self
    }

    /// Set the human-readable service description.
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    /// Router-only: set Max-Connections from global advertised limit if not set.
    pub(crate) fn with_max_connections(&mut self, n: usize) {
        self.max_connections = Some(n);
    }

    /// Set `Options-TTL` (seconds).
    pub fn with_options_ttl(mut self, ttl: u32) -> Self {
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

    /// Set Preview size (bytes).
    pub fn with_preview(mut self, preview: u32) -> Self {
        self.preview = Some(preview);
        self
    }

    /// Add rule for a file extension (e.g. "pdf", "exe").
    pub fn add_transfer_rule(mut self, extension: &str, behavior: TransferBehavior) -> Self {
        self.transfer_rules.insert(extension.to_string(), behavior);
        self
    }

    /// Set default transfer behavior (applied when an extension is not matched).
    pub fn with_default_transfer_behavior(mut self, behavior: TransferBehavior) -> Self {
        self.default_transfer_behavior = Some(behavior);
        self
    }

    /// Add a custom header.
    pub fn add_custom_header(mut self, name: &str, value: &str) -> Self {
        self.custom_headers
            .insert(name.to_string(), value.to_string());
        self
    }

    /// Set opt-body and its type.
    pub fn with_opt_body(mut self, body_type: &str, body: Vec<u8>) -> Self {
        self.opt_body_type = Some(body_type.to_string());
        self.opt_body = Some(body);
        self
    }

    /// Router-only: inject the supported ICAP methods.
    pub(crate) fn set_methods<M>(&mut self, methods: M)
    where
        M: Into<SmallVec<Method, 2>>,
    {
        self.methods = methods.into();
    }

    /// Get the ISTag for a specific request (static or dynamic).
    #[inline]
    pub fn istag_for(&self, req: &Request) -> String {
        self.istag.current_for(req)
    }

    /// Build an ICAP `OPTIONS` response for **this specific request**.
    ///
    /// The response includes:
    /// - `Methods` — from the injected method set
    /// - `ISTag`   — resolved via the static string or dynamic provider
    /// - Standard headers (`Encapsulated`, `Service`, `Max-Connections`, etc.)
    ///
    pub fn build_response_for(&self, req: &Request) -> Response {
        let mut response = Response::new(StatusCode::OK, "OK");

        let methods_str = self
            .methods
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        response = response.add_header("Methods", &methods_str);

        // ISTag — dynamic per-request
        let istag_now = self.istag_for(req);
        response = response.add_header("ISTag", &format!("\"{}\"", istag_now));

        // Encapsulated
        let encapsulated_value = if self.opt_body.is_some() {
            "opt-body=0"
        } else {
            "null-body=0"
        };
        response = response.add_header("Encapsulated", encapsulated_value);

        if let Some(ref service) = self.service {
            response = response.add_header("Service", service);
        }
        if let Some(max_conn) = self.max_connections {
            response = response.add_header("Max-Connections", &max_conn.to_string());
        }
        if let Some(ttl) = self.options_ttl {
            response = response.add_header("Options-TTL", &ttl.to_string());
        }
        if let Some(ref service_id) = self.service_id {
            response = response.add_header("Service-ID", service_id);
        }
        if !self.allow.is_empty() {
            response = response.add_header("Allow", &self.allow.join(", "));
        }
        if let Some(preview) = self.preview {
            response = response.add_header("Preview", &preview.to_string());
        }
        if let Some(ref opt_body_type) = self.opt_body_type {
            response = response.add_header("Opt-body-type", opt_body_type);
        }

        // Transfer-* headers
        if !self.transfer_rules.is_empty() {
            let mut preview_extensions = Vec::new();
            let mut ignore_extensions = Vec::new();
            let mut complete_extensions = Vec::new();

            for (ext, behavior) in &self.transfer_rules {
                match behavior {
                    TransferBehavior::Preview => preview_extensions.push(ext.clone()),
                    TransferBehavior::Ignore => ignore_extensions.push(ext.clone()),
                    TransferBehavior::Complete => complete_extensions.push(ext.clone()),
                }
            }
            if let Some(ref default_behavior) = self.default_transfer_behavior {
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

        // Custom headers
        for (name, value) in &self.custom_headers {
            response = response.add_header(name, value);
        }
        // Optional body
        if let Some(ref opt_body) = self.opt_body {
            response = response.with_body(opt_body);
        }

        response
    }

    /// Validate invariants for this configuration.
    ///
    /// For dynamic ISTag providers it is not possible to validate non-emptiness
    /// at configuration time; perform validation when computing the value if needed.
    pub fn validate(&self) -> Result<(), String> {
        // No eager validation for dynamic ISTag; keep other invariants.
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
}
