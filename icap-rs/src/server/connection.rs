use std::collections::HashMap;
use std::sync::Arc;

use smallvec::SmallVec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{trace, warn};

use crate::error::IcapResult;
use crate::protocol::{
    dechunk_icap_entity, dechunk_icap_entity_with_ieof, find_double_crlf,
    parse_encapsulated_header, parse_preview_header_value, read_chunked_to_end,
    read_chunked_until_zero,
};
use crate::request::{
    IncomingRequest, RequestParserMode, parse_icap_request, parse_icap_request_with_mode,
};
use crate::{Body, EmbeddedHttp, Method, Response, ServiceOptions, StatusCode};

use super::Server;
use super::preview::{PreviewDecision, mark_request_body_as_preview};
use super::router::{RouteEntry, resolve_service};
impl Server {
    /// Handle a single client connection (persistent / keep-alive).
    ///
    /// Reads one full ICAP message (headers + chunked body if any), parses and dispatches it,
    /// writes the response, then repeats until the peer closes the connection.
    pub(super) async fn handle_connection<S>(
        mut socket: S,
        routes: Arc<HashMap<String, RouteEntry>>,
        aliases: Arc<HashMap<String, String>>,
        default_service: Option<String>,
        advertised_max_conn: Option<usize>,
        request_parser_mode: RequestParserMode,
        addr: std::net::SocketAddr,
    ) -> IcapResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];

        loop {
            // === Read headers ===
            let h_end = loop {
                if let Some(end) = find_double_crlf(&buf) {
                    break end;
                }

                let n = match socket.read(&mut tmp).await {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return if buf.is_empty() {
                            Ok(())
                        } else {
                            Err("EOF before complete ICAP headers".into())
                        };
                    }
                    Err(e) => return Err(e.into()),
                };

                if n == 0 {
                    return if buf.is_empty() {
                        Ok(())
                    } else {
                        Err("EOF before complete ICAP headers".into())
                    };
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let hdr_text = if let Ok(text) = std::str::from_utf8(&buf[..h_end]) {
                text.to_string()
            } else {
                Self::write_wire_error_response(
                    &mut socket,
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                )
                .await?;
                return Ok(());
            };
            let enc = match parse_encapsulated_header(&hdr_text) {
                Ok(enc) => enc,
                Err(err) => {
                    warn!(client=%addr, error=%err, "malformed ICAP Encapsulated header");
                    Self::write_wire_parse_error_response(&mut socket, &err).await?;
                    return Ok(());
                }
            };
            let mut msg_end = h_end;

            if let Some(body_rel) = enc.req_body.or(enc.res_body) {
                let body_abs = h_end + body_rel;
                while buf.len() < body_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before start of ICAP body".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                let preview_size = parse_preview_header_value(&hdr_text);
                if preview_size.is_some() {
                    let (preview_end, preview_ieof) =
                        read_chunked_until_zero(&mut socket, &mut buf, body_abs).await?;

                    let mut preview_slice = &buf[body_abs..preview_end];
                    let (mut decoded, _ieof_seen) =
                        dechunk_icap_entity_with_ieof(&mut preview_slice)
                            .map_err(|e| format!("dechunk ICAP preview entity: {e}"))?;

                    if preview_ieof {
                        msg_end = preview_end;
                    } else {
                        let mut preview_buf = buf.clone();
                        let preview_len = decoded.len();
                        preview_buf.splice(body_abs..preview_end, decoded.clone());
                        let preview_msg_end = body_abs + preview_len;
                        let mut preview_req = match parse_request_for_mode(
                            &preview_buf[..preview_msg_end],
                            request_parser_mode,
                        ) {
                            Ok(req) => req,
                            Err(err) => {
                                warn!(client=%addr, error=%err, "malformed ICAP preview request");
                                Self::write_wire_parse_error_response(&mut socket, &err).await?;
                                return Ok(());
                            }
                        };
                        let preview_method = preview_req.method;
                        let preview_raw_service = preview_req
                            .service
                            .rsplit('/')
                            .next()
                            .unwrap_or(&preview_req.service);
                        let preview_service_resolved = resolve_service(
                            preview_raw_service,
                            &aliases,
                            default_service.as_deref(),
                        );

                        if let Some(entry) = routes.get(preview_service_resolved.as_ref())
                            && let Some(handler_entry) = entry.handlers.get(&preview_method)
                            && handler_entry.preview_aware
                        {
                            mark_request_body_as_preview(&mut preview_req, false);
                            match (handler_entry.handler)(preview_req).await? {
                                PreviewDecision::Continue => {}
                                PreviewDecision::Respond(resp) => {
                                    let should_close = !matches!(
                                        resp.status_code,
                                        StatusCode::OK
                                            | StatusCode::NO_CONTENT
                                            | StatusCode::PARTIAL_CONTENT
                                    );
                                    let resp = if should_close {
                                        resp.add_header("Connection", "close")
                                    } else {
                                        resp
                                    };
                                    let bytes = resp.to_raw()?;
                                    socket.write_all(&bytes).await?;
                                    trace!(
                                        client = %addr,
                                        "Preview final response sent with status {}",
                                        resp.status_code
                                    );

                                    if should_close {
                                        let _ = socket.shutdown().await;
                                        return Ok(());
                                    }

                                    buf.drain(..preview_end);
                                    continue;
                                }
                            }
                        }

                        socket.write_all(b"ICAP/1.0 100 Continue\r\n\r\n").await?;
                        socket.flush().await?;

                        let rest_end =
                            read_chunked_to_end(&mut socket, &mut buf, preview_end).await?;
                        let mut rest_slice = &buf[preview_end..rest_end];
                        let (rest_decoded, _) = dechunk_icap_entity_with_ieof(&mut rest_slice)
                            .map_err(|e| format!("dechunk ICAP remainder entity: {e}"))?;
                        decoded.extend_from_slice(&rest_decoded);
                        msg_end = rest_end;
                    }

                    let decoded_len = decoded.len();
                    buf.splice(body_abs..msg_end, decoded);
                    msg_end = body_abs + decoded_len;
                } else {
                    msg_end = read_chunked_to_end(&mut socket, &mut buf, body_abs).await?;
                    if msg_end > body_abs {
                        let mut chunked_slice = &buf[body_abs..msg_end];
                        let decoded = dechunk_icap_entity(&mut chunked_slice)
                            .map_err(|e| format!("dechunk ICAP entity: {e}"))?;
                        let decoded_len = decoded.len();
                        buf.splice(body_abs..msg_end, decoded);
                        msg_end = body_abs + decoded_len;
                    }
                }
            } else if let Some(end_rel) = enc.null_body {
                let end_abs = h_end + end_rel;
                while buf.len() < end_abs {
                    let n = socket.read(&mut tmp).await?;
                    if n == 0 {
                        return Err("Unexpected EOF before null-body boundary".into());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                msg_end = end_abs;
            }

            // === Parse + route ===
            let req = match parse_request_for_mode(&buf[..msg_end], request_parser_mode) {
                Ok(req) => req,
                Err(err) => {
                    warn!(client=%addr, error=%err, "malformed ICAP request");
                    Self::write_wire_parse_error_response(&mut socket, &err).await?;
                    return Ok(());
                }
            };
            let method = req.method;
            let raw_service: &str = req.service.rsplit('/').next().unwrap_or(&req.service);
            let service_resolved =
                resolve_service(raw_service, &aliases, default_service.as_deref());
            trace!(
                client = %addr,
                method = ?method,
                service = %service_resolved,
                "received request"
            );

            let resp = if let Some(entry) = routes.get(service_resolved.as_ref()) {
                if method == Method::Options {
                    let mut allowed: SmallVec<Method, 2> = entry.handlers.keys().copied().collect();
                    allowed.sort_unstable();
                    let mut cfg = entry.options.as_ref().map_or_else(
                        || {
                            ServiceOptions::new()
                                .with_static_istag(&format!("{service_resolved}-default-1.0"))
                                .with_options_ttl(3600)
                                .allow_204()
                                .allow_206()
                        },
                        Clone::clone,
                    );
                    cfg.set_methods(allowed);
                    if cfg.service.is_none() {
                        cfg = cfg
                            .with_service(&format!("ICAP Service {}", service_resolved.as_ref()));
                    }
                    if let (Some(n), None) = (advertised_max_conn, cfg.max_connections) {
                        cfg.with_max_connections(n);
                    }
                    cfg.build_response_for(&req)
                } else {
                    let allow_204 = req.allow_204;
                    let allow_206 = req.allow_206;
                    let has_preview = req.icap_headers.get("Preview").is_some();

                    if !allow_204 && !has_preview {
                        let istag_now = entry.options.as_ref().map_or_else(
                            || format!("{service_resolved}-default-1.0"),
                            |opts| opts.istag_for(&req),
                        );

                        if allow_206
                            && let Some(out) =
                                Self::build_206_use_original_body(&req, method, &istag_now)?
                        {
                            out
                        } else {
                            let mut out = Response::ok_with_istag(&istag_now)?;

                            match (&req.embedded, method) {
                                (
                                    Some(EmbeddedHttp::Resp {
                                        head,
                                        body: Body::Full { reader },
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
                                        format!("build http::Response from embedded: {e}")
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
                                        format!("build http::Request from embedded: {e}")
                                    })?;
                                    out = out.with_http_request(&http_req)?;
                                }
                                _ => {}
                            }

                            out
                        }
                    } else if let Some(handler_entry) = entry.handlers.get(&method) {
                        match (handler_entry.handler)(req).await? {
                            PreviewDecision::Respond(resp) => resp,
                            PreviewDecision::Continue => {
                                return Err(
                                    "Route handler returned Continue after full body was read"
                                        .into(),
                                );
                            }
                        }
                    } else {
                        Response::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
                    }
                }
            } else {
                trace!(client=%addr, service=%service_resolved, "service not found");
                Response::new(StatusCode::NOT_FOUND, "Service Not Found")
            };

            let should_close = !matches!(
                resp.status_code,
                StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::PARTIAL_CONTENT
            );
            let resp = if should_close {
                resp.add_header("Connection", "close")
            } else {
                resp
            };

            let bytes = resp.to_raw()?;
            socket.write_all(&bytes).await?;
            trace!(
                client = %addr,
                "Response sent with status {}",
                resp.status_code
            );

            if should_close {
                let _ = socket.shutdown().await;
                return Ok(());
            }
            buf.drain(..msg_end);
        }
    }
}

fn parse_request_for_mode(
    data: &[u8],
    mode: RequestParserMode,
) -> IcapResult<IncomingRequest<Vec<u8>>> {
    match mode {
        RequestParserMode::Strict => parse_icap_request(data),
        RequestParserMode::Compatibility => parse_icap_request_with_mode(data, mode),
    }
}
