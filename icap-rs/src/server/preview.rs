use crate::request::{Body, IncomingRequest, Remainder};
use crate::{EmbeddedHttp, Response};

/// Decision returned by a preview-aware route handler.
///
/// Returning [`PreviewDecision::Respond`] lets a service send a final ICAP
/// response after seeing only preview bytes, before the server emits
/// `ICAP/1.0 100 Continue` and before the client uploads the remainder.
#[derive(Debug)]
#[must_use]
pub enum PreviewDecision {
    /// Continue the normal Preview flow.
    ///
    /// The server sends `ICAP/1.0 100 Continue`, reads the remaining chunked
    /// body, and invokes the same route again with a full body.
    Continue,
    /// Send this final ICAP response immediately.
    ///
    /// The server does not emit `100 Continue` and does not read the remainder
    /// of the request body.
    Respond(Response),
}

pub(super) fn mark_request_body_as_preview(req: &mut IncomingRequest, ieof: bool) {
    let Some(embedded) = req.embedded.as_mut() else {
        return;
    };

    let body = match embedded {
        EmbeddedHttp::Req { body, .. } | EmbeddedHttp::Resp { body, .. } => body,
    };

    let Body::Full { reader } = body else {
        return;
    };

    let preview = std::mem::take(reader);
    *body = Body::Preview {
        bytes: preview,
        ieof,
        remainder: Remainder::new(Vec::new(), None),
    };
}
