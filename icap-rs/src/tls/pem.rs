//! PEM loaders shared between server and client TLS configuration.
//!
//! All helpers return [`TlsError`] (not `std::io::Error`) so that callers
//! can distinguish PEM problems from connection-level network failures.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::error::TlsError;

/// Load a certificate chain (leaf first, intermediates after) from a PEM file.
pub(crate) fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = File::open(path).map_err(|e| TlsError::pem_io(path, e))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::pem_parse(path, e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::pem_parse(path, "no certificates found"));
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
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsError::pem_parse(path, e.to_string()))?;
    key.ok_or_else(|| TlsError::NoPrivateKey(path.to_path_buf()))
}

/// Load certificates from a PEM file and add them as trust roots.
///
/// Used both for server-side client-auth CA bundles and for client-side
/// custom trust roots.
pub(crate) fn load_roots_into(store: &mut RootCertStore, path: &Path) -> Result<usize, TlsError> {
    let certs = load_cert_chain(path)?;
    let mut added = 0usize;
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| TlsError::ConfigBuild(format!("add CA from {}: {e}", path.display())))?;
        added += 1;
    }
    Ok(added)
}
