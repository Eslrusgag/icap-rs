use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;

use crate::{IncomingRequest, Method, Response};

use super::handler::HandlerResult;
use super::options::ServiceOptions;
use super::preview::PreviewDecision;

/// A per-service ICAP handler.
///
/// One handler can serve multiple ICAP methods declared for a service via
/// [`crate::ServerBuilder::route`].
pub(super) type RequestHandler = Box<
    dyn Fn(
            IncomingRequest,
        )
            -> std::pin::Pin<Box<dyn Future<Output = HandlerResult<PreviewDecision>> + Send>>
        + Send
        + Sync,
>;

/// Return type adapter for route handlers.
///
/// Handlers returning `HandlerResult<Response>` keep the full-body behavior:
/// the server reads the whole request body before invoking them. Handlers
/// returning `HandlerResult<PreviewDecision>` are preview-aware and may be
/// invoked before `100 Continue`. If a preview-aware handler returns
/// [`PreviewDecision::Continue`], the server sends `100 Continue`, reads the
/// remainder, and invokes the same route again with `Body::Full`.
pub trait RouteOutput: Send + 'static {
    const PREVIEW_AWARE: bool;

    fn into_preview_decision(self) -> HandlerResult<PreviewDecision>;
}

impl RouteOutput for HandlerResult<Response> {
    const PREVIEW_AWARE: bool = false;

    fn into_preview_decision(self) -> HandlerResult<PreviewDecision> {
        self.map(PreviewDecision::Respond)
    }
}

impl RouteOutput for HandlerResult<PreviewDecision> {
    const PREVIEW_AWARE: bool = true;

    fn into_preview_decision(self) -> HandlerResult<PreviewDecision> {
        self
    }
}

pub(super) struct HandlerEntry {
    pub(super) handler: RequestHandler,
    pub(super) preview_aware: bool,
}

/// Route entry for a service: per-method handlers plus optional OPTIONS config.
pub(super) struct RouteEntry {
    pub(super) handlers: HashMap<Method, HandlerEntry>,
    pub(super) options: Option<ServiceOptions>,
}

/// Resolve default service and bounded alias rewrites.
///
/// Rules:
/// - If `raw` is empty or exactly "/", use `default_service` (when set).
/// - Apply up to 4 alias rewrites (`from` -> `to`) to avoid cycles.
pub(super) fn resolve_service<'a>(
    raw: &'a str,
    aliases: &'a HashMap<String, String>,
    default_service: Option<&'a str>,
) -> Cow<'a, str> {
    let mut cur: Cow<'a, str> = if raw.is_empty() || raw == "/" {
        default_service.map_or(Cow::Borrowed(raw), Cow::Borrowed)
    } else {
        Cow::Borrowed(raw)
    };

    for _ in 0..4 {
        if let Some(next) = aliases.get(cur.as_ref()) {
            cur = Cow::Borrowed(next.as_str());
        } else {
            break;
        }
    }

    cur
}
