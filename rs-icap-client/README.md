# rs-icap-client

A Rust implementation of an ICAP client with a command-line interface similar to c-icap-client.

## Features

- Full ICAP protocol support (OPTIONS, REQMOD, RESPMOD)
- TLS support (planned)
- File input/output support
- Custom header support
- Debug logging
- Preview data support
- Allow 204/206 support

## Installation

```bash
cargo build --release
```

## Usage

```bash
rs-icap-client [OPTIONS]
```

### Basic Options

- `-V, --version` - Print version and exit
- `--VV` - Print version and build information and exit
- `-i, --icap-servername <SERVER>` - The ICAP server name (default: localhost)
- `-p, --port <PORT>` - The server port (default: 1344)
- `-s, --service <SERVICE>` - The service name (default: options)

### TLS Options

- `--tls` - Use TLS (not yet implemented)
- `--tls-method <METHOD>` - Use TLS method (not yet implemented)
- `--tls-no-verify` - Disable server certificate verify (not yet implemented)

### Request Options

- `-f, --filename <FILE>` - Send this file to the ICAP server
- `-o, --output <FILE>` - Save output to this file (default: stdout)
- `--method <METHOD>` - Use specific ICAP method
- `--req <URL>` - Send a request modification for the specified URL
- `--resp <URL>` - Send a response modification for the specified URL

### Debug and Verbose Options

- `-d, --debug-level <LEVEL>` - Debug level info to stdout (1-5)
- `-v, --verbose` - Print response headers

### ICAP Protocol Options

- `--noreshdr` - Do not send reshdr headers
- `--nopreview` - Do not send preview data
- `--no204` - Do not allow 204 outside preview
- `--206` - Support allow 206
- `-w, --preview-size <SIZE>` - Set maximum preview data size

### Custom Headers

- `-x, --xheader <HEADER>` - Include header in ICAP request headers
- `--hx <HEADER>` - Include header in HTTP request headers
- `--rhx <HEADER>` - Include header in HTTP response headers

## Examples

### Basic OPTIONS request

```bash
rs-icap-client -i localhost -p 1344 -s options
```

### REQMOD request with file

```bash
rs-icap-client -i localhost -p 1344 -s reqmod --req http://example.com -f input.html
```

### RESPMOD request with custom headers

```bash
rs-icap-client -i localhost -p 1344 -s respmod --resp http://example.com \
  -x "X-Custom-Header: value" \
  --hx "User-Agent: CustomClient/1.0" \
  -o output.html
```

### Verbose output with debug

```bash
rs-icap-client -i localhost -p 1344 -s options -v -d 3
```

### With preview data

```bash
rs-icap-client -i localhost -p 1344 -s reqmod --req http://example.com \
  -f input.html -w 1024
```

## Building from Source

```bash
git clone <repository-url>
cd rs-icap-client
cargo build --release
```

## Dependencies

- `icap-rs` - ICAP protocol library
- `clap` - Command-line argument parsing
- `tokio` - Async runtime
- `tracing` - Logging framework
- `anyhow` - Error handling

## License

This project is licensed under the same license as the icap-rs library.

