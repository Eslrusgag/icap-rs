//! PEM loaders shared between server and client TLS configuration.
//!
//! All helpers return [`TlsError`] (not `std::io::Error`) so that callers
//! can distinguish PEM problems from connection-level network failures.

use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::error::TlsError;

/// Load a certificate chain (leaf first, intermediates after) from a PEM file.
pub(crate) fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::pem_io(path, e))?;
    let mut reader = BufReader::new(file);
    parse_cert_chain_reader(path.display().to_string(), &mut reader)
}

/// Parse a certificate chain (leaf first, intermediates after) from PEM bytes.
pub(crate) fn parse_cert_chain(
    source: impl Into<String>,
    pem: impl AsRef<[u8]>,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = Cursor::new(pem.as_ref());
    parse_cert_chain_reader(source, &mut reader)
}

fn parse_cert_chain_reader(
    source: impl Into<String>,
    reader: &mut impl std::io::BufRead,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let source = source.into();
    let certs = rustls_pemfile::certs(reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::pem_parse(&source, e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::pem_parse(source, "no certificates found"));
    }
    Ok(certs)
}

/// Load a single private key from a PEM file.
///
/// Supports PKCS#8, PKCS#1 (RSA) and SEC1 (EC) formats — whichever
/// `rustls_pemfile::private_key` recognises in the input.
pub(crate) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::pem_io(path, e))?;
    let mut reader = BufReader::new(file);
    parse_private_key_reader(path.display().to_string(), &mut reader)
}

/// Parse a single private key from PEM bytes.
pub(crate) fn parse_private_key(
    source: impl Into<String>,
    pem: impl AsRef<[u8]>,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = Cursor::new(pem.as_ref());
    parse_private_key_reader(source, &mut reader)
}

fn parse_private_key_reader(
    source: impl Into<String>,
    reader: &mut impl std::io::BufRead,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    let source = source.into();
    let key = rustls_pemfile::private_key(reader)
        .map_err(|e| TlsError::pem_parse(&source, e.to_string()))?;
    key.ok_or_else(|| TlsError::NoPrivateKey(source.into()))
}

/// Load certificates from a PEM file and add them as trust roots.
///
/// Used both for server-side client-auth CA bundles and for client-side
/// custom trust roots.
pub(crate) fn load_roots_into(store: &mut RootCertStore, path: &Path) -> Result<usize, TlsError> {
    let certs = load_cert_chain(path)?;
    let source = path.display().to_string();
    add_roots(store, &source, certs)
}

/// Parse certificates from PEM bytes and add them as trust roots.
pub(crate) fn parse_roots_into(
    store: &mut RootCertStore,
    source: impl Into<String>,
    pem: impl AsRef<[u8]>,
) -> Result<usize, TlsError> {
    let source = source.into();
    let certs = parse_cert_chain(&source, pem)?;
    add_roots(store, &source, certs)
}

fn add_roots(
    store: &mut RootCertStore,
    source: &str,
    certs: Vec<CertificateDer<'static>>,
) -> Result<usize, TlsError> {
    let mut added = 0usize;
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| TlsError::ConfigBuild(format!("add CA from {source}: {e}")))?;
        added += 1;
    }
    Ok(added)
}
