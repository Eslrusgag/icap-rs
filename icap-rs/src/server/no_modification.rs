use crate::error::IcapResult;
use crate::request::{Body, IncomingRequest};
use crate::{EmbeddedHttp, Method, Response};

use super::Server;

impl Server {
    /// Build a `206 Partial Content` response that tells the ICAP client to use
    /// the original, unmodified HTTP body (`use-original-body=0`).
    ///
    /// Returns `None` when the request does not carry a full embedded body (e.g.
    /// null-body or no embedded message), so the caller can fall back to a
    /// `200` echo.
    pub(super) fn build_206_use_original_body(
        req: &IncomingRequest,
        method: Method,
        istag: &str,
    ) -> IcapResult<Option<Response>> {
        let out = Response::partial_content_with_istag(istag)?;

        let out = match (&req.embedded, method) {
            (
                Some(EmbeddedHttp::Resp {
                    head,
                    body: Body::Full { .. },
                    ..
                }),
                Method::RespMod,
            ) => out.with_http_response_head_and_original_body(head, 0)?,
            (
                Some(EmbeddedHttp::Req {
                    head,
                    body: Body::Full { .. },
                }),
                Method::ReqMod,
            ) => out.with_http_request_head_and_original_body(head, 0)?,
            _ => return Ok(None),
        };

        Ok(Some(out))
    }

    /// Build a `200 OK` response that echoes the embedded HTTP message from the
    /// request back to the ICAP client unchanged.
    ///
    /// Used when a handler returns `204 No Content` but the client did not
    /// advertise `Allow: 204` (RFC 3507 §4.6), so the server cannot send 204
    /// and must return the full HTTP message instead.
    pub(super) fn build_200_echo_response(
        req: &IncomingRequest,
        method: Method,
        istag: &str,
    ) -> IcapResult<Response> {
        let mut out = Response::ok_with_istag(istag)?;
        match (&req.embedded, method) {
            (
                Some(EmbeddedHttp::Resp {
                    head,
                    body: Body::Full { reader },
                    ..
                }),
                Method::RespMod,
            ) => {
                let mut builder = http::Response::builder()
                    .status(head.status())
                    .version(head.version());
                if let Some(h) = builder.headers_mut() {
                    h.extend(head.headers().clone());
                }
                let http_resp = builder.body(reader.clone()).map_err(|e| {
                    crate::error::Error::body(format!("build http::Response from embedded: {e}"))
                })?;
                out = out.with_http_response(&http_resp)?;
            }
            (
                Some(EmbeddedHttp::Req {
                    head,
                    body: Body::Full { reader },
                }),
                Method::ReqMod,
            ) => {
                let mut builder = http::Request::builder()
                    .method(head.method().clone())
                    .uri(head.uri().clone())
                    .version(head.version());
                if let Some(h) = builder.headers_mut() {
                    h.extend(head.headers().clone());
                }
                let http_req = builder.body(reader.clone()).map_err(|e| {
                    crate::error::Error::body(format!("build http::Request from embedded: {e}"))
                })?;
                out = out.with_http_request(&http_req)?;
            }
            _ => {}
        }
        Ok(out)
    }
}
