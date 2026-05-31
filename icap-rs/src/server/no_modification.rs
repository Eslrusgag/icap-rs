use crate::error::IcapResult;
use crate::request::{Body, IncomingRequest};
use crate::{EmbeddedHttp, Method, Response};

use super::Server;

impl Server {
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
}
