# Squid Interoperability Demo

This demo runs Squid as an HTTP proxy in Docker and points its ICAP `REQMOD`
and `RESPMOD` hooks at the `icap-rs` example server running on the host
machine, not inside Docker.

It is intentionally configured with `bypass=0`: Squid should fail visibly when
the ICAP service is unavailable or rejects a request. That makes protocol
interop problems easier to see.

## Run

Terminal 1, on the host machine:

```bash
cargo run -p icap-rs --example squid_interop_server
```

By default the example listens on `[::]:1344`. On Docker Desktop for Windows,
Squid reaches the host service through the Docker Desktop host gateway address
`192.168.65.254`, which is used in `squid.conf`. To force a specific bind
address:

```bash
ICAP_LISTEN=0.0.0.0:1344 cargo run -p icap-rs --example squid_interop_server
```

Terminal 2:

```bash
docker compose -f interop/squid/compose.yaml up
```

## Check Squid Behavior

Normal request, adapted by `RESPMOD`:

```bash
curl -v -x http://127.0.0.1:3128 http://origin/
```

Expected signal:

- HTTP response includes `X-ICAP-Respmod: icap-rs`.
- The Rust server logs a `Squid REQMOD` line and a `Squid RESPMOD` line.
- Squid logs the proxied request to stdout.

Blocked by `REQMOD` before origin fetch:

```bash
curl -v -x http://127.0.0.1:3128 http://origin/blocked
```

Expected signal:

- HTTP response status is `403 Forbidden`.
- HTTP response includes `X-ICAP-Reqmod: icap-rs`.
- The Rust server logs `blocked=true` for `Squid REQMOD`.
- Squid may log `WARNING: Squid bug 5187 workaround triggered` after serving
  the adapted `REQMOD` error response. In this demo that warning is expected:
  it is emitted by Squid after it consumes the encapsulated HTTP response body,
  while the client still receives the ICAP-generated `403` response.

Service unavailable behavior:

1. Stop the Rust ICAP server.
2. Keep Squid running.
3. Repeat the `curl` request.

Expected signal:

- Squid returns an error instead of bypassing ICAP, because both ICAP services
  are configured with `bypass=0`.

## Check the ICAP Client Directly

These commands bypass Squid and test the Rust ICAP client against the Rust ICAP
server. Keep the `squid_interop_server` example running on the host.

Fetch `OPTIONS` for `REQMOD`:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/reqmod \
  -m OPTIONS \
  -v
```

Expected signal:

- ICAP status is `200 OK`.
- Headers include `Methods: REQMOD`, `Allow: 204`, and `Preview: 0`.

Send an allowed `REQMOD` request:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/reqmod \
  --req http://origin/
```

Expected signal:

- ICAP status is `204 No Content`.
- The server logs `Squid REQMOD ... blocked=false`.

Send a blocked `REQMOD` request:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/reqmod \
  --req http://origin/blocked \
  -v
```

Expected signal:

- ICAP status is `200 OK`.
- The encapsulated HTTP response is `403 Forbidden`.
- Headers include `X-ICAP-Reqmod: icap-rs` and
  `X-Block-Reason: blocked URL path`.
- The server logs `Squid REQMOD ... blocked=true`.

Send a `RESPMOD` request using the demo origin page as the HTTP response body:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/respmod \
  --resp http://origin/ \
  -f interop/squid/origin/index.html \
  -v
```

Expected signal:

- ICAP status is `200 OK`.
- The adapted HTTP response includes `X-ICAP-Respmod: icap-rs`.
- The server logs `Squid RESPMOD status=200 OK body="full"`.

Print the generated ICAP request without sending it:

```bash
cargo run -p rs-icap-client -- \
  -u icap://127.0.0.1:1344/reqmod \
  --req http://origin/blocked \
  --print-request
```

Use this when you want to inspect the exact ICAP request line, headers, and
`Encapsulated` offsets produced by the client.

## Notes

- This tests plain HTTP proxying. HTTPS traffic would require Squid SSL bumping
  before `RESPMOD` can see response bodies.
- `192.168.65.254` is the Docker Desktop host gateway address used by the Squid
  container to reach the Rust process running on the Windows host. If your Docker
  setup uses a different gateway, verify it from the Squid container and update
  the ICAP URLs in `squid.conf`.
