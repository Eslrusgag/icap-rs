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
//! captured at `OPTIONS` time; [`OptionsCache::reconcile_istag`] implements
//! that rule.

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

/// A cached `OPTIONS` result for a single service endpoint.
#[derive(Debug, Clone)]
pub(crate) struct CachedOptions {
    /// `ISTag` captured at `OPTIONS` time, used to detect server config changes.
    istag: Option<String>,
    /// Instant after which the entry is considered stale.
    expires_at: Instant,
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
        Some(Self { istag, expires_at })
    }

    /// Whether the entry has not yet expired.
    fn is_fresh(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Parse the `Options-TTL` header (integer seconds) into a [`Duration`].
fn parse_options_ttl(response: &ParsedResponse) -> Option<Duration> {
    let raw = response.get_header("Options-TTL")?.to_str().ok()?;
    let seconds: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

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
