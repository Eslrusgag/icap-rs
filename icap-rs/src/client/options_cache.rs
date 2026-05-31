//! Client-side OPTIONS response cache (RFC 3507 §4.10 / §5).
//!
//! When enabled on a [`ClientBuilder`](crate::ClientBuilder), the client may
//! fetch an `OPTIONS` response for a service once and reuse it for subsequent
//! `REQMOD`/`RESPMOD` requests until it expires. Per RFC 3507 §4.10.2 the
//! lifetime is taken from the `Options-TTL` header; when the server omits it,
//! the configured [`OptionsCacheConfig::default_ttl`] is used instead. With
//! neither a header nor a configured fallback the response is **not** cached.
//!
//! RFC 3507 §5 requires the client to invalidate a cached entry when the
//! `ISTag` observed on a later `REQMOD`/`RESPMOD` response differs from the one
//! captured at `OPTIONS` time; `OptionsCache::reconcile_istag` implements
//! that rule.
//!
//! RFC 3507 §4.10.2 defines `Transfer-Preview`, `Transfer-Ignore`, and
//! `Transfer-Complete` headers that tell the client how to handle objects by
//! file extension. `OptionsCache::resolve_transfer` looks up the action for a
//! given extension from the cached OPTIONS response.

use crate::response::ParsedResponse;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for the client-side OPTIONS cache.
///
/// The cache is opt-in: a [`Client`](crate::Client) only caches `OPTIONS`
/// responses when a configuration is supplied via
/// [`ClientBuilder::with_options_cache`](crate::ClientBuilder::with_options_cache).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use icap_rs::OptionsCacheConfig;
///
/// // Cache OPTIONS for 5 minutes when the server does not send `Options-TTL`.
/// let config = OptionsCacheConfig::new().with_default_ttl(Duration::from_secs(300));
/// assert_eq!(config.default_ttl(), Some(Duration::from_secs(300)));
/// ```
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct OptionsCacheConfig {
    default_ttl: Option<Duration>,
}

impl OptionsCacheConfig {
    /// Create a configuration with no fallback TTL.
    ///
    /// With no fallback, only responses that carry an `Options-TTL` header are
    /// cached.
    pub const fn new() -> Self {
        Self { default_ttl: None }
    }

    /// Set the fallback lifetime used when a response has no `Options-TTL`.
    pub const fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    /// Return the configured fallback lifetime, if any.
    #[must_use]
    pub const fn default_ttl(&self) -> Option<Duration> {
        self.default_ttl
    }
}

// ---------------------------------------------------------------------------
// Transfer-* policy (RFC 3507 §4.10.2)
// ---------------------------------------------------------------------------

/// Action the client should take for a request based on the server's
/// `Transfer-Preview`, `Transfer-Ignore`, and `Transfer-Complete` OPTIONS
/// response headers (RFC 3507 §4.10.2).
///
/// Priority (highest first): `Full` > `Skip` > `Preview`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransferAction {
    /// Send the complete body without preview (`Transfer-Complete`).
    Full,
    /// Skip the ICAP transaction; return a synthetic 204 without contacting
    /// the server (`Transfer-Ignore`).
    Skip,
    /// Send the first `n` bytes as a preview and wait for `100 Continue`
    /// (`Transfer-Preview`). `n` is taken from the OPTIONS `Preview` header.
    Preview(usize),
}

// ---------------------------------------------------------------------------
// CachedOptions
// ---------------------------------------------------------------------------

/// A cached `OPTIONS` result for a single service endpoint.
#[derive(Debug, Clone)]
pub(crate) struct CachedOptions {
    /// `ISTag` captured at `OPTIONS` time.
    istag: Option<String>,
    /// Instant after which the entry is considered stale.
    expires_at: Instant,
    /// File extensions for which the server requests preview bytes.
    transfer_preview: Vec<String>,
    /// File extensions that the server wants bypassed (no ICAP scan).
    transfer_ignore: Vec<String>,
    /// File extensions for which the server wants the full body (no preview).
    transfer_complete: Vec<String>,
    /// Preview size (bytes) advertised in the OPTIONS `Preview` header.
    /// Used as the preview length when `Transfer-Preview` matches.
    preview_size: Option<usize>,
}

impl CachedOptions {
    /// Build a cache entry from a parsed `OPTIONS` response.
    ///
    /// Returns `None` when no lifetime can be determined: the `Options-TTL`
    /// header (in seconds) takes precedence, otherwise the configured
    /// [`OptionsCacheConfig::default_ttl`]. With neither, the response is not
    /// cacheable. Also returns `None` if the resulting expiry instant would
    /// overflow.
    pub(crate) fn from_response(
        response: &ParsedResponse,
        config: &OptionsCacheConfig,
    ) -> Option<Self> {
        let ttl = parse_options_ttl(response).or_else(|| config.default_ttl())?;
        let expires_at = Instant::now().checked_add(ttl)?;
        let istag = response
            .get_header("ISTag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        Some(Self {
            istag,
            expires_at,
            transfer_preview: parse_extensions(response, "Transfer-Preview"),
            transfer_ignore: parse_extensions(response, "Transfer-Ignore"),
            transfer_complete: parse_extensions(response, "Transfer-Complete"),
            preview_size: parse_preview_size(response),
        })
    }

    /// Whether the entry has not yet expired.
    fn is_fresh(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Determine the transfer action for a request based on its file extension.
    ///
    /// Returns `None` when the extension does not match any of the server's
    /// `Transfer-*` policies and the request should proceed with its own
    /// preview settings.
    ///
    /// Priority (RFC 3507 §4.10.2): `Full` > `Skip` > `Preview`.
    fn transfer_action(&self, file_ext: &str) -> Option<TransferAction> {
        let matches = |list: &[String]| list.iter().any(|e| e == "*" || e == file_ext);

        if matches(&self.transfer_complete) {
            return Some(TransferAction::Full);
        }
        if matches(&self.transfer_ignore) {
            return Some(TransferAction::Skip);
        }
        if matches(&self.transfer_preview) {
            return Some(TransferAction::Preview(self.preview_size.unwrap_or(0)));
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Header parsing helpers
// ---------------------------------------------------------------------------

/// Parse the `Options-TTL` header (integer seconds) into a [`Duration`].
fn parse_options_ttl(response: &ParsedResponse) -> Option<Duration> {
    let raw = response.get_header("Options-TTL")?.to_str().ok()?;
    let seconds: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

/// Parse the `Preview` header (integer bytes) for use as a preview size.
fn parse_preview_size(response: &ParsedResponse) -> Option<usize> {
    let raw = response.get_header("Preview")?.to_str().ok()?;
    raw.trim().parse().ok()
}

/// Parse a `Transfer-*` header as a comma-separated list of lowercase
/// file extensions (without leading dot). `"*"` is preserved as-is.
fn parse_extensions(response: &ParsedResponse, header: &str) -> Vec<String> {
    let Some(value) = response.get_header(header) else {
        return Vec::new();
    };
    let Ok(s) = value.to_str() else {
        return Vec::new();
    };
    s.split(',')
        .map(|e| e.trim().to_lowercase())
        .filter(|e| !e.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// OptionsCache
// ---------------------------------------------------------------------------

/// Cache key: target host, port, and normalized service path.
type CacheKey = (String, u16, String);

/// Concurrent store of cached `OPTIONS` results keyed by service endpoint.
#[derive(Debug)]
pub(crate) struct OptionsCache {
    config: OptionsCacheConfig,
    entries: RwLock<HashMap<CacheKey, CachedOptions>>,
}

impl OptionsCache {
    /// Create an empty cache with the given configuration.
    pub(crate) fn new(config: OptionsCacheConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Return the cache configuration.
    pub(crate) const fn config(&self) -> &OptionsCacheConfig {
        &self.config
    }

    /// Whether a fresh (non-expired) entry exists for the endpoint.
    pub(crate) async fn has_fresh(&self, host: &str, port: u16, path: &str) -> bool {
        let key = (host.to_string(), port, path.to_string());
        let entries = self.entries.read().await;
        entries.get(&key).is_some_and(CachedOptions::is_fresh)
    }

    /// Insert or replace the cached entry for the endpoint.
    pub(crate) async fn store(&self, host: &str, port: u16, path: &str, entry: CachedOptions) {
        let key = (host.to_string(), port, path.to_string());
        let mut entries = self.entries.write().await;
        entries.insert(key, entry);
    }

    /// Return the server-requested transfer action for `file_ext` based on
    /// the cached OPTIONS response (RFC 3507 §4.10.2).
    ///
    /// Returns `None` when there is no fresh cache entry or when the extension
    /// does not match any `Transfer-*` policy. In that case the caller should
    /// use the request's own preview settings unchanged.
    pub(crate) async fn resolve_transfer(
        &self,
        host: &str,
        port: u16,
        path: &str,
        file_ext: &str,
    ) -> Option<TransferAction> {
        let key = (host.to_string(), port, path.to_string());
        let entries = self.entries.read().await;
        let entry = entries.get(&key)?;
        if !entry.is_fresh() {
            return None;
        }
        entry.transfer_action(file_ext)
    }

    /// Invalidate the cached entry when an observed `ISTag` differs from the
    /// captured one.
    ///
    /// A missing `observed` value carries no information and leaves the cache
    /// untouched. This implements the RFC 3507 §5 rule that a changed `ISTag`
    /// on a `REQMOD`/`RESPMOD` response makes the cached `OPTIONS` stale.
    pub(crate) async fn reconcile_istag(
        &self,
        host: &str,
        port: u16,
        path: &str,
        observed: Option<&str>,
    ) {
        let Some(observed) = observed else {
            return;
        };
        let key = (host.to_string(), port, path.to_string());

        // Fast path (warm cache, no ISTag change): read lock only.
        {
            let entries = self.entries.read().await;
            let Some(entry) = entries.get(&key) else {
                return;
            };
            if entry.istag.as_deref() == Some(observed) {
                return;
            }
        }

        // Slow path: ISTag changed — acquire write lock and remove the entry.
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get(&key)
            && entry.istag.as_deref() != Some(observed)
        {
            entries.remove(&key);
        }
    }

    /// Drop every cached entry, forcing a re-fetch on the next request.
    pub(crate) async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}
