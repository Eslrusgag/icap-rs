use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{trace, warn};

use crate::error::{Error, IcapResult};
use crate::protocol::{
    dechunk_icap_entity, dechunk_icap_entity_with_ieof, find_double_crlf,
    parse_encapsulated_header, parse_preview_header_value, read_chunked_to_end,
    read_chunked_until_zero,
};
use crate::request::{
    IncomingRequest, RequestParserMode, parse_icap_request, parse_icap_request_with_mode,
};
use crate::{Body, EmbeddedHttp, Method, Response, StatusCode};

use super::Server;
use super::options::OptionsResponseBuilder;
use super::preview::{PreviewDecision, mark_request_body_as_preview};
use super::router::{RouteEntry, resolve_service};
use super::timeouts::ServerTimeouts;

async fn with_timeout_as<T, F>(
    dur: Option<Duration>,
    fut: F,
    mk_err: fn(Duration) -> Error,
) -> IcapResult<T>
where
    F: std::future::Future<Output = IcapResult<T>>,
{
    if let Some(d) = dur {
        match timeout(d, fut).await {
            Ok(res) => res,
            Err(_) => Err(mk_err(d)),
        }
    } else {
        fut.await
    }
}

async fn write_all_with_timeout<S>(
    socket: &mut S,
    bytes: &[u8],
    dur: Option<Duration>,
) -> IcapResult<()>
where
    S: AsyncWrite + Unpin,
{
    with_timeout_as(
        dur,
        async {
            socket.write_all(bytes).await?;
            Ok(())
        },
        Error::server_write_timeout,
    )
    .await
}

async fn flush_with_timeout<S>(socket: &mut S, dur: Option<Duration>) -> IcapResult<()>
where
    S: AsyncWrite + Unpin,
{
    with_timeout_as(
        dur,
        async {
            socket.flush().await?;
            Ok(())
        },
        Error::server_write_timeout,
    )
    .await
}
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
        timeouts: ServerTimeouts,
        addr: std::net::SocketAddr,
    ) -> IcapResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut tmp = [0u8; 8192];
        // Byte offset into `buf` where the current (unprocessed) request starts.
        // Avoids O(N) Vec::drain on every keep-alive request.
        let mut buf_start: usize = 0;

        loop {
            // First read of each new request gets the idle keep-alive deadline
            // (it may legitimately wait a long time on a kept-alive connection);
            // subsequent reads of the same header block use the tighter
            // header_read deadline.
            let mut request_started = !(buf_start == buf.len());

            // === Read headers ===
            let h_end = loop {
                if let Some(end) = find_double_crlf(&buf[buf_start..]) {
                    break buf_start + end;
                }

                if buf.len() - buf_start > crate::MAX_HDR_BYTES {
                    Self::write_wire_error_response(
                        &mut socket,
                        StatusCode::BAD_REQUEST,
                        "Request Header Too Large",
                    )
                    .await?;
                    return Ok(());
                }

                let (read_dur, mk_err): (Option<Duration>, fn(Duration) -> Error) =
                    if request_started {
                        (timeouts.header_read, Error::server_header_read_timeout)
                    } else {
                        (
                            timeouts.idle_keepalive.or(timeouts.header_read),
                            if timeouts.idle_keepalive.is_some() {
                                Error::server_idle_timeout
                            } else {
                                Error::server_header_read_timeout
                            },
                        )
                    };

                let read_res = with_timeout_as(
                    read_dur,
                    async { socket.read(&mut tmp).await.map_err(Error::Io) },
                    mk_err,
                )
                .await;

                let n = match read_res {
                    Ok(n) => n,
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return if buf_start == buf.len() {
                            Ok(())
                        } else {
                            Err(Error::Protocol(crate::error::ProtocolError::EarlyClose))
                        };
                    }
                    Err(e) => return Err(e),
                };

                if n == 0 {
                    return if buf_start == buf.len() {
                        Ok(())
                    } else {
                        Err(Error::Protocol(crate::error::ProtocolError::EarlyClose))
                    };
                }
                buf.extend_from_slice(&tmp[..n]);
                request_started = true;
            };

            // Parse header fields as &str — avoids a String allocation.
            // Both enc and preview_size must be extracted before buf is mutated.
            let Ok(hdr_str) = std::str::from_utf8(&buf[buf_start..h_end]) else {
                Self::write_wire_error_response(
                    &mut socket,
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                )
                .await?;
                return Ok(());
            };
            let enc = parse_encapsulated_header(hdr_str);
            let preview_size = parse_preview_header_value(hdr_str);
            // RFC 3507 §4.2: honour Connection: close from the client.
            let client_wants_close = hdr_str
                .split("\r\n")
                .skip(1) // skip request-line
                .filter_map(|line| line.split_once(':'))
                .any(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("connection")
                        && value
                            .split(',')
                            .any(|t| t.trim().eq_ignore_ascii_case("close"))
                });
            // Last use of hdr_str; NLL ends the borrow here so buf can be mutated below.
            let enc = match enc {
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
                    let n = with_timeout_as(
                        timeouts.body_read,
                        async { socket.read(&mut tmp).await.map_err(Error::Io) },
                        Error::server_body_read_timeout,
                    )
                    .await?;
                    if n == 0 {
                        return Err(Error::body("unexpected EOF before start of ICAP body"));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }

                if preview_size.is_some() {
                    let (preview_end, preview_ieof) = with_timeout_as(
                        timeouts.body_read,
                        async { read_chunked_until_zero(&mut socket, &mut buf, body_abs).await },
                        Error::server_body_read_timeout,
                    )
                    .await?;

                    let mut preview_slice = &buf[body_abs..preview_end];
                    let (mut decoded, _ieof_seen) =
                        dechunk_icap_entity_with_ieof(&mut preview_slice).map_err(|e| {
                            Error::body(format!("dechunk ICAP preview entity: {e}"))
                        })?;

                    if preview_ieof {
                        msg_end = preview_end;
                    } else {
                        // Build a minimal parse buffer: ICAP headers + dechunked preview body.
                        // Avoids cloning the entire `buf` (which may be much larger).
                        let preview_len = decoded.len();
                        let mut parse_buf =
                            Vec::with_capacity((body_abs - buf_start) + preview_len);
                        parse_buf.extend_from_slice(&buf[buf_start..body_abs]);
                        parse_buf.extend_from_slice(&decoded);
                        let mut preview_req = match parse_request_for_mode(
                            &parse_buf,
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
                            let log_service = preview_service_resolved.to_string();
                            mark_request_body_as_preview(&mut preview_req, false);
                            preview_req.istag = entry
                                .options
                                .as_ref()
                                .and_then(|o| o.istag_for(&preview_req).ok());
                            let decision = match (handler_entry.handler)(preview_req).await {
                                Ok(d) => d,
                                Err(err) => {
                                    warn!(
                                        client = %addr,
                                        service = %log_service,
                                        method = %preview_method,
                                        error = %err,
                                        "preview handler returned error"
                                    );
                                    PreviewDecision::Respond(err.into_response())
                                }
                            };
                            match decision {
                                PreviewDecision::Continue => {}
                                PreviewDecision::Respond(resp) => {
                                    let should_close = client_wants_close
                                        || !matches!(
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
                                    write_all_with_timeout(&mut socket, &bytes, timeouts.write)
                                        .await?;
                                    trace!(
                                        client = %addr,
                                        "Preview final response sent with status {}",
                                        resp.status_code
                                    );

                                    if should_close {
                                        let _ = socket.shutdown().await;
                                        return Ok(());
                                    }

                                    // Advance past preview bytes without O(N) drain.
                                    advance_buf(&mut buf, &mut buf_start, preview_end);
                                    continue;
                                }
                            }
                        }

                        write_all_with_timeout(
                            &mut socket,
                            b"ICAP/1.0 100 Continue\r\n\r\n",
                            timeouts.write,
                        )
                        .await?;
                        flush_with_timeout(&mut socket, timeouts.write).await?;

                        let rest_end = with_timeout_as(
                            timeouts.body_read,
                            async { read_chunked_to_end(&mut socket, &mut buf, preview_end).await },
                            Error::server_body_read_timeout,
                        )
                        .await?;
                        let mut rest_slice = &buf[preview_end..rest_end];
                        let (rest_decoded, _) = dechunk_icap_entity_with_ieof(&mut rest_slice)
                            .map_err(|e| {
                                Error::body(format!("dechunk ICAP remainder entity: {e}"))
                            })?;
                        decoded.extend_from_slice(&rest_decoded);
                        msg_end = rest_end;
                    }

                    let decoded_len = decoded.len();
                    buf.splice(body_abs..msg_end, decoded);
                    msg_end = body_abs + decoded_len;
                } else {
                    msg_end = with_timeout_as(
                        timeouts.body_read,
                        async { read_chunked_to_end(&mut socket, &mut buf, body_abs).await },
                        Error::server_body_read_timeout,
                    )
                    .await?;
                    if msg_end > body_abs {
                        let mut chunked_slice = &buf[body_abs..msg_end];
                        let decoded = dechunk_icap_entity(&mut chunked_slice)
                            .map_err(|e| Error::body(format!("dechunk ICAP entity: {e}")))?;
                        let decoded_len = decoded.len();
                        buf.splice(body_abs..msg_end, decoded);
                        msg_end = body_abs + decoded_len;
                    }
                }
            } else if let Some(end_rel) = enc.null_body {
                let end_abs = h_end + end_rel;
                while buf.len() < end_abs {
                    let n = with_timeout_as(
                        timeouts.body_read,
                        async { socket.read(&mut tmp).await.map_err(Error::Io) },
                        Error::server_body_read_timeout,
                    )
                    .await?;
                    if n == 0 {
                        return Err(Error::body("unexpected EOF before null-body boundary"));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                msg_end = end_abs;
            }

            // === Parse + route ===
            let mut req =
                match parse_request_for_mode(&buf[buf_start..msg_end], request_parser_mode) {
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
                    let mut allowed: Vec<Method> = entry.handlers.keys().copied().collect();
                    allowed.sort_unstable();
                    let methods_str = allowed
                        .iter()
                        .enumerate()
                        .fold(String::new(), |mut s, (i, m)| {
                            if i > 0 {
                                s.push_str(", ");
                            }
                            s.push_str(m.as_str());
                            s
                        });
                    let Some(mut cfg) = entry.options.clone() else {
                        return Err(Error::service(format!(
                            "Service '{}' has no explicit OPTIONS configuration with ISTag",
                            service_resolved.as_ref()
                        )));
                    };
                    if cfg.service.is_none() {
                        cfg = cfg
                            .with_service(&format!("ICAP Service {}", service_resolved.as_ref()));
                    }
                    if let (Some(n), None) = (advertised_max_conn, cfg.max_connections) {
                        cfg.with_max_connections(n);
                    }
                    OptionsResponseBuilder::new(&cfg, &methods_str).build(&req)?
                } else {
                    let allow_204 = req.allow_204;
                    let allow_206 = req.allow_206;
                    let has_preview = req.icap_headers.get("Preview").is_some();

                    if !allow_204 && !has_preview {
                        let Some(options) = entry.options.as_ref() else {
                            return Err(Error::service(format!(
                                "Service '{}' has no explicit OPTIONS configuration with ISTag",
                                service_resolved.as_ref()
                            )));
                        };
                        let istag_now = options.istag_for(&req)?;

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
                                        Error::body(format!(
                                            "build http::Response from embedded: {e}"
                                        ))
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
                                        Error::body(format!(
                                            "build http::Request from embedded: {e}"
                                        ))
                                    })?;
                                    out = out.with_http_request(&http_req)?;
                                }
                                _ => {}
                            }

                            out
                        }
                    } else if let Some(handler_entry) = entry.handlers.get(&method) {
                        let log_service = service_resolved.to_string();
                        req.istag = entry.options.as_ref().and_then(|o| o.istag_for(&req).ok());
                        match (handler_entry.handler)(req).await {
                            Ok(PreviewDecision::Respond(resp)) => resp,
                            Ok(PreviewDecision::Continue) => {
                                warn!(
                                    client = %addr,
                                    service = %log_service,
                                    method = %method,
                                    "handler returned Continue after full body was read; \
                                     sending 500"
                                );
                                Response::new(StatusCode::INTERNAL_SERVER_ERROR, "Handler error")
                            }
                            Err(err) => {
                                warn!(
                                    client = %addr,
                                    service = %log_service,
                                    method = %method,
                                    error = %err,
                                    "handler returned error"
                                );
                                err.into_response()
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

            let should_close = client_wants_close
                || !matches!(
                    resp.status_code,
                    StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::PARTIAL_CONTENT
                );
            let resp = if should_close {
                resp.add_header("Connection", "close")
            } else {
                resp
            };

            let bytes = resp.to_raw()?;
            write_all_with_timeout(&mut socket, &bytes, timeouts.write).await?;
            trace!(
                client = %addr,
                "Response sent with status {}",
                resp.status_code
            );

            if should_close {
                let _ = socket.shutdown().await;
                return Ok(());
            }
            advance_buf(&mut buf, &mut buf_start, msg_end);
        }
    }
}

/// Advance `buf_start` past `new_start`, compacting the buffer when it is cost-effective.
///
/// - If all bytes have been consumed, clear the buffer in O(1) without any copy.
/// - If more than half the capacity is dead space, drain the prefix (one copy of the
///   remainder, but resets `buf_start` to 0 for future requests).
/// - Otherwise, just advance the cursor — no copy at all.
#[inline]
fn advance_buf(buf: &mut Vec<u8>, buf_start: &mut usize, new_start: usize) {
    *buf_start = new_start;
    if *buf_start == buf.len() {
        buf.clear();
        *buf_start = 0;
    } else if *buf_start >= buf.capacity() / 2 {
        buf.drain(..*buf_start);
        *buf_start = 0;
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
