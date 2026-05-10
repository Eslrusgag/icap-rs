# Changelog

## Unreleased

### Breaking

- ICAP responses with embedded HTTP now use RFC 3507 framing: `req-hdr`/`res-hdr` bytes are sent unchunked, and ICAP chunked coding starts only at `req-body`/`res-body`/`opt-body`. The previous invalid wire format that chunked `HTTP head + HTTP body` as one block is not supported.
- Response parsing now rejects legacy unchunked entity bytes after a `req-body`/`res-body`/`opt-body` offset. Peers must send an ICAP chunked entity body at that offset.

### Fixed

- `Client` and `Response::from_raw` now read RFC-compliant embedded HTTP responses as `Response.body = HTTP head + dechunked HTTP body`, without chunk-size metadata.
