//! ICAP OPTIONS configuration (WIP).
//!
//! This module provides types to build an ICAP `OPTIONS` response for a given
//! service. It includes:
//! - [`IcapMethod`] — ICAP methods
//! - [`TransferBehavior`] — per-extension transfer hints (Preview/Ignore/Complete)
//! - [`OptionsConfig`] — a builder-like struct that serializes to an ICAP response
//! - [`IcapOptionsBuilder`] — fluent builder that validates the config
//!
//! Status: **work in progress** — covers common headers used by popular ICAP
//! servers/clients. Extend as needed for your deployment.

use crate::response::{Response, StatusCode};
use chrono::{DateTime, Utc};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt;

/// ICAP methods supported by a service.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum IcapMethod {
    ReqMod,
    RespMod,
    Options,
}

impl fmt::Display for IcapMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcapMethod::ReqMod => write!(f, "REQMOD"),
            IcapMethod::RespMod => write!(f, "RESPMOD"),
            IcapMethod::Options => write!(f, "OPTIONS"),
        }
    }
}

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

/// Configuration for generating an ICAP `OPTIONS` response.
#[derive(Debug, Clone)]
pub struct OptionsConfig {
    /// Supported ICAP methods
    pub(crate) methods: SmallVec<IcapMethod, 2>,
    /// Human-readable service description (optional).
    pub service: Option<String>,
    /// Service tag (REQUIRED). A unique identifier for the service configuration.
    pub istag: String,
    /// Max concurrent connections hint (optional).
    pub max_connections: Option<u32>,
    /// TTL (seconds) for caching the OPTIONS response (optional).
    pub options_ttl: Option<u32>,
    /// Server date (optional). If set, formatted as HTTP-date (GMT).
    pub date: Option<DateTime<Utc>>,
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

impl OptionsConfig {
    /// Create a new OPTIONS config with required fields.
    pub fn new(istag: &str) -> Self {
        Self {
            methods: SmallVec::new(),
            service: None,
            istag: istag.to_string(),
            max_connections: None,
            options_ttl: None,
            date: None,
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

    /// Set the human-readable service description.
    pub fn with_service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    /// Router-only: set Max-Connections from global advertised limit if not set.
    pub(crate) fn with_max_connections(&mut self, n: u32) {
        self.max_connections = Some(n);
    }

    /// Set `Options-TTL` (seconds).
    pub fn with_options_ttl(mut self, ttl: u32) -> Self {
        self.options_ttl = Some(ttl);
        self
    }

    /// Set server date (UTC).
    pub fn with_date(mut self, date: DateTime<Utc>) -> Self {
        self.date = Some(date);
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
        M: Into<SmallVec<IcapMethod, 2>>,
    {
        self.methods = methods.into();
    }

    /// Build an ICAP `OPTIONS` response from this config.
    ///
    /// Assumes the router injected a non-empty `methods` list.
    pub fn build_response(&self) -> Response {
        let mut response = Response::new(StatusCode::Ok200, "OK");

        // Methods
        let methods_str = self
            .methods
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        response = response.add_header("Methods", &methods_str);

        // ISTag
        response = response.add_header("ISTag", &format!("\"{}\"", self.istag));

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
        if let Some(date) = self.date {
            response = response.add_header(
                "Date",
                &date.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            );
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
    /// `methods` may be empty here — the router will inject them before
    /// `build_response()` is called.
    pub fn validate(&self) -> Result<(), String> {
        if self.istag.is_empty() {
            return Err("ISTag cannot be empty".to_string());
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
}

/// Fluent builder for [`OptionsConfig`].
///
/// Prefer using this builder over constructing [`OptionsConfig`] directly when
/// you want validation via [`IcapOptionsBuilder::build`].
pub struct IcapOptionsBuilder {
    config: OptionsConfig,
}

impl IcapOptionsBuilder {
    /// Start a new builder (methods will be injected by the router).
    pub fn new(istag: &str) -> Self {
        Self {
            config: OptionsConfig::new(istag),
        }
    }

    /// Set service description.
    pub fn service(mut self, service: &str) -> Self {
        self.config = self.config.with_service(service);
        self
    }

    /// Set `Options-TTL` (seconds).
    pub fn options_ttl(mut self, ttl: u32) -> Self {
        self.config = self.config.with_options_ttl(ttl);
        self
    }

    /// Set current UTC date.
    pub fn with_current_date(mut self) -> Self {
        self.config = self.config.with_date(Utc::now());
        self
    }

    /// Set service ID.
    pub fn service_id(mut self, service_id: &str) -> Self {
        self.config = self.config.with_service_id(service_id);
        self
    }

    /// Add `204` to `Allow`.
    pub fn allow_204(mut self) -> Self {
        self.config = self.config.add_allow("204");
        self
    }

    /// Set Preview size (bytes).
    pub fn preview(mut self, preview: u32) -> Self {
        self.config = self.config.with_preview(preview);
        self
    }

    /// Add a per-extension transfer rule.
    pub fn transfer_rule(mut self, extension: &str, behavior: TransferBehavior) -> Self {
        self.config = self.config.add_transfer_rule(extension, behavior);
        self
    }

    /// Set default transfer behavior (`*`).
    pub fn default_transfer_behavior(mut self, behavior: TransferBehavior) -> Self {
        self.config = self.config.with_default_transfer_behavior(behavior);
        self
    }

    /// Add a custom header.
    pub fn custom_header(mut self, name: &str, value: &str) -> Self {
        self.config = self.config.add_custom_header(name, value);
        self
    }

    /// Finish and validate.
    pub fn build(self) -> Result<OptionsConfig, String> {
        self.config.validate()?;
        Ok(self.config)
    }
}
