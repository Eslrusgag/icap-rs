# Changelog

## Unreleased

### Added

- Added `PreviewDecision` route handlers, allowing services to return a final response after preview bytes or continue with `100 Continue` from the regular route.
- Added `preview_decision_server` example for preview-time final responses.

### Breaking

- ICAP responses with embedded HTTP now use RFC 3507 framing: `req-hdr`/`res-hdr` bytes are sent unchunked, and ICAP chunked coding starts only at `req-body`/`res-body`/`opt-body`. The previous invalid wire format that chunked `HTTP head + HTTP body` as one block is not supported.
- Response parsing now rejects legacy unchunked entity bytes after a `req-body`/`res-body`/`opt-body` offset. Peers must send an ICAP chunked entity body at that offset.
- Removed the separate `ServerBuilder::route_preview` API; preview decisions now belong to regular `route`/`route_reqmod` handlers returning `IcapResult<PreviewDecision>`.

### Fixed

- `Client` and `Response::from_raw` now read RFC-compliant embedded HTTP responses as `Response.body = HTTP head + dechunked HTTP body`, without chunk-size metadata.
- Server request parsing now returns ICAP `400 Bad Request` for malformed wire requests and `501 Not Implemented` for unknown methods.
- Request parsing now rejects method-incompatible `Encapsulated` forms, `null-body` mixed with body tokens, and `OPTIONS` without `Encapsulated` unless compatibility mode is explicitly enabled.
- Added `Allow: 206` no-modification responses using the `use-original-body` partial-content marker.
- `rs-icap-client` now reconstructs `206 Partial Content` output by appending the original request body suffix from the `use-original-body` offset.
- Updated the RFC 3507 supported/unsupported implementation plans to reflect the current release scope and remaining specification gaps.
