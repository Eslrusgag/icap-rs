//! TLS / ICAPS integration tests.
//!
//! RFC 3507 is silent on ICAPS — these tests pin the project's TLS
//! conventions (ICAPS over `icaps://` on port 11344 by default) and
//! verify that protocol-level TLS errors surface through the dedicated
//! [`TlsError`] variants rather than collapsing into generic
//! [`Error::Network`] failures.

#![cfg(feature = "tls-rustls")]

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use icap_rs::error::Error;
use icap_rs::server::options::ServiceOptions;
use icap_rs::tls::{ClientTlsConfig, ServerTlsConfig, TlsError};
use icap_rs::{Client, IncomingRequest, Method, Request, Response, Server};

use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
	Issuer, KeyPair, KeyUsagePurpose,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ISTAG: &str = "tls-test-1";

/// Unique scratch directory under the system temp dir so parallel test
/// processes do not stomp on each other's PEM files.
fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("icap-rs-tls-tests-{pid}-{n}"));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn write_pem(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).expect("create pem file");
    f.write_all(contents.as_bytes()).expect("write pem");
    path
}

struct TestPki {
    _dir: PathBuf,
    ca_pem_path: PathBuf,
    server_cert_pem_path: PathBuf,
    server_key_pem_path: PathBuf,
    /// Optional client cert/key, populated by `with_client_cert`.
    client_cert_pem_path: Option<PathBuf>,
    client_key_pem_path: Option<PathBuf>,
}

impl TestPki {
    /// Generate a fresh self-signed CA and a server cert valid for `dns_name`.
    fn new(dns_name: &str) -> Self {
        let dir = scratch_dir();

        // Self-signed CA
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "icap-rs Test CA");
        ca_params.distinguished_name = dn;
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        // Server cert signed by CA
        let mut server_params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
        let mut sdn = DistinguishedName::new();
        sdn.push(DnType::CommonName, dns_name);
        server_params.distinguished_name = sdn;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("server key");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let server_cert_pem = server_cert.pem();
        let server_key_pem = server_key.serialize_pem();

        let ca_pem_path = write_pem(&dir, "ca.pem", &ca_pem);
        let server_cert_pem_path = write_pem(&dir, "server.crt", &server_cert_pem);
        let server_key_pem_path = write_pem(&dir, "server.key", &server_key_pem);

        Self {
            _dir: dir,
            ca_pem_path,
            server_cert_pem_path,
            server_key_pem_path,
            client_cert_pem_path: None,
            client_key_pem_path: None,
        }
    }

    /// Generate CA + server cert + client cert in a single shot so we keep
    /// the CA `Issuer` alive across both signing operations.
    fn new_with_client(server_dns: &str, client_cn: &str) -> Self {
        let dir = scratch_dir();

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "icap-rs Test CA");
        ca_params.distinguished_name = dn;
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut server_params = CertificateParams::new(vec![server_dns.to_string()]).unwrap();
        let mut sdn = DistinguishedName::new();
        sdn.push(DnType::CommonName, server_dns);
        server_params.distinguished_name = sdn;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("server key");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut cdn = DistinguishedName::new();
        cdn.push(DnType::CommonName, client_cn);
        client_params.distinguished_name = cdn;
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client cert");

        let ca_pem_path = write_pem(&dir, "ca.pem", &ca_pem);
        let server_cert_pem_path = write_pem(&dir, "server.crt", &server_cert.pem());
        let server_key_pem_path = write_pem(&dir, "server.key", &server_key.serialize_pem());
        let client_cert_pem_path = Some(write_pem(&dir, "client.crt", &client_cert.pem()));
        let client_key_pem_path = Some(write_pem(&dir, "client.key", &client_key.serialize_pem()));

        Self {
            _dir: dir,
            ca_pem_path,
            server_cert_pem_path,
            server_key_pem_path,
            client_cert_pem_path,
            client_key_pem_path,
        }
    }
}

/// One-shot install of the rustls crypto provider for test runs that build
/// `rustls::ClientConfig` outside of the crate's [`crate::tls`] helpers.
fn install_provider_once() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn echo_204_handler(_req: IncomingRequest) -> icap_rs::IcapResult<Response> {
    Response::no_content_with_istag(ISTAG)
}

/// Spin up an ICAPS server bound to an ephemeral port and return its address.
/// Returns the server's `JoinHandle` so the test can keep it alive.
async fn spawn_server(
    tls: ServerTlsConfig,
) -> (SocketAddr, tokio::task::JoinHandle<icap_rs::IcapResult<()>>) {
    let server = Server::builder()
        .bind("127.0.0.1:0")
        .with_tls(tls)
        .route(
            "scan",
            [Method::ReqMod, Method::RespMod],
            echo_204_handler,
            Some(ServiceOptions::new().with_static_istag(ISTAG).allow_204()),
        )
        .build()
        .await
        .expect("build server");
    let addr = server.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move { server.run().await });
    (addr, handle)
}

fn unwrap_tls(err: &Error) -> &TlsError {
    match err {
        Error::Tls(e) => e,
        other => panic!("expected Error::Tls, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn icaps_handshake_success_with_custom_ca() {
    // RFC 3507 is silent on TLS — this validates the ICAPS convention.
    let pki = TestPki::new("localhost");

    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls");
    let (addr, _server) = spawn_server(server_tls).await;

    let client_tls = ClientTlsConfig::empty()
        .add_root_ca_pem(&pki.ca_pem_path)
        .expect("add ca")
        .with_sni("localhost");
    let client = Client::builder()
        .with_uri(&format!("icaps://localhost:{}/scan", addr.port()))
        .expect("uri")
        .with_tls(client_tls)
        .build();

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(&Request::options("scan")),
    )
    .await
    .expect("handshake completes")
    .expect("ICAPS OPTIONS succeeds");
    assert_eq!(resp.status_code().as_u16(), 200);
}

#[tokio::test]
async fn icaps_handshake_fails_with_untrusted_ca() {
    // Cert chain validation failure must surface as Error::Tls, not Error::Network.
    let pki = TestPki::new("localhost");
    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls");
    let (addr, _server) = spawn_server(server_tls).await;

    // Client uses an empty trust store — server's self-signed CA is unknown.
    let client_tls = ClientTlsConfig::empty().with_sni("localhost");
    let client = Client::builder()
        .with_uri(&format!("icaps://localhost:{}/scan", addr.port()))
        .expect("uri")
        .with_tls(client_tls)
        .build();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(&Request::options("scan")),
    )
    .await
    .expect("handshake completes")
    .expect_err("handshake must fail without trust roots");
    let tls_err = unwrap_tls(&err);
    assert!(
        matches!(tls_err, TlsError::Handshake(_)),
        "expected TlsError::Handshake, got {tls_err:?}"
    );
}

#[tokio::test]
async fn icaps_invalid_sni_is_rejected_before_connect() {
    let pki = TestPki::new("localhost");
    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls");
    let (addr, _server) = spawn_server(server_tls).await;

    // SNI containing characters not allowed in DNS names.
    let client_tls = ClientTlsConfig::empty()
        .add_root_ca_pem(&pki.ca_pem_path)
        .expect("add ca")
        .with_sni("not a valid !! sni");
    let client = Client::builder()
        .host("127.0.0.1")
        .port(addr.port())
        .with_tls(client_tls)
        .build();

    let err = client
        .send(&Request::options("scan"))
        .await
        .expect_err("invalid SNI must fail");
    let tls_err = unwrap_tls(&err);
    assert!(
        matches!(tls_err, TlsError::InvalidServerName(_)),
        "expected TlsError::InvalidServerName, got {tls_err:?}"
    );
}

#[tokio::test]
async fn icaps_handshake_times_out_against_silent_peer() {
    // Bind a bare TCP listener that accepts but never speaks TLS.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent tcp");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            // Hold accepted sockets open without writing anything.
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Keep the socket alive past the client-side handshake timeout.
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sock);
            });
        }
    });

    let client_tls = ClientTlsConfig::empty()
        .with_sni("localhost")
        .with_handshake_timeout(Duration::from_millis(250));
    let client = Client::builder()
        .host("127.0.0.1")
        .port(addr.port())
        .with_tls(client_tls)
        .build();

    let err = client
        .send(&Request::options("scan"))
        .await
        .expect_err("silent peer must trigger timeout");
    let tls_err = unwrap_tls(&err);
    assert!(
        matches!(tls_err, TlsError::HandshakeTimeout(_)),
        "expected TlsError::HandshakeTimeout, got {tls_err:?}"
    );
}

#[tokio::test]
async fn icaps_mtls_accepts_valid_client_cert() {
    let pki = TestPki::new_with_client("localhost", "icap-rs-test-client");
    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls")
            .with_client_auth_pem(&pki.ca_pem_path)
            .expect("require client auth");
    let (addr, _server) = spawn_server(server_tls).await;

    let client_tls = ClientTlsConfig::empty()
        .add_root_ca_pem(&pki.ca_pem_path)
        .expect("add ca")
        .with_client_auth_pem(
            pki.client_cert_pem_path.as_ref().unwrap(),
            pki.client_key_pem_path.as_ref().unwrap(),
        )
        .expect("client auth")
        .with_sni("localhost");
    let client = Client::builder()
        .with_uri(&format!("icaps://localhost:{}/scan", addr.port()))
        .expect("uri")
        .with_tls(client_tls)
        .build();

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(&Request::options("scan")),
    )
    .await
    .expect("handshake completes")
    .expect("mTLS OPTIONS succeeds");
    assert_eq!(resp.status_code().as_u16(), 200);
}

#[tokio::test]
async fn icaps_mtls_rejects_missing_client_cert() {
    let pki = TestPki::new_with_client("localhost", "icap-rs-test-client");
    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls")
            .with_client_auth_pem(&pki.ca_pem_path)
            .expect("require client auth");
    let (addr, _server) = spawn_server(server_tls).await;

    // Client does NOT present a certificate.
    let client_tls = ClientTlsConfig::empty()
        .add_root_ca_pem(&pki.ca_pem_path)
        .expect("add ca")
        .with_sni("localhost");
    let client = Client::builder()
        .with_uri(&format!("icaps://localhost:{}/scan", addr.port()))
        .expect("uri")
        .with_tls(client_tls)
        .build();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(&Request::options("scan")),
    )
    .await
    .expect("handshake completes")
    .expect_err("server should refuse handshake without client cert");
    // In TLS 1.3 the server's `certificate_required` alert is emitted after
    // its Finished, so the client's handshake itself succeeds and the failure
    // surfaces during the first read as `Error::Network` whose source chain
    // contains the rustls alert. In TLS 1.2 the same condition aborts the
    // handshake and arrives as `Error::Tls(Handshake)`. Both are correct.
    assert!(
        is_tls_layer_failure(&err),
        "expected a TLS-layer rejection, got {err:?}"
    );
}

/// Returns `true` when the error originates from TLS (either as a structured
/// [`TlsError`] or as an `Error::Network` whose source chain mentions a rustls
/// alert / certificate condition).
fn is_tls_layer_failure(err: &Error) -> bool {
    if matches!(err, Error::Tls(_)) {
        return true;
    }
    if let Error::Network(io_err) = err {
        let mut src: Option<&(dyn std::error::Error + 'static)> = Some(io_err);
        while let Some(e) = src {
            let msg = e.to_string();
            if msg.contains("Alert")
                || msg.contains("alert")
                || msg.contains("certificate")
                || msg.contains("Certificate")
            {
                return true;
            }
            src = e.source();
        }
    }
    false
}

#[tokio::test]
async fn icaps_default_port_is_11344() {
    // Sanity: `with_uri("icaps://host/...")` resolves to 11344 without an
    // explicit port. We don't actually connect — TCP connect failure is fine.
    let client = Client::builder()
        .with_uri("icaps://does-not-resolve.invalid/scan")
        .expect("uri parses")
        .build();
    let err = client
        .send(&Request::options("scan"))
        .await
        .expect_err("connection must fail");
    // We expect a Network error (DNS / refused), not a config error.
    assert!(
        matches!(err, Error::Network(_)),
        "expected Network failure, got {err:?}"
    );
}

#[tokio::test]
async fn dangerous_disable_cert_verification_accepts_self_signed() {
    // Mirrors c-icap-client's `-tls-no-verify` flag.
    let pki = TestPki::new("localhost");
    let server_tls =
        ServerTlsConfig::from_pem_files(&pki.server_cert_pem_path, &pki.server_key_pem_path)
            .expect("server tls");
    let (addr, _server) = spawn_server(server_tls).await;

    install_provider_once();

    let client_tls = ClientTlsConfig::empty()
        .dangerous_disable_cert_verification()
        .expect("disable verify")
        .with_sni("any-name-works-now");
    let client = Client::builder()
        .with_uri(&format!("icaps://localhost:{}/scan", addr.port()))
        .expect("uri")
        .with_tls(client_tls)
        .build();

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(&Request::options("scan")),
    )
    .await
    .expect("handshake completes")
    .expect("insecure ICAPS succeeds");
    assert_eq!(resp.status_code().as_u16(), 200);
}
