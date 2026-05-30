//! Rustls client config — Mozilla CA bundle, TLS 1.2/1.3, ring backend.
//!
//! Built once per process and shared between Electrum, the CEX HTTPS fetchers,
//! and any future TLS clients. Construction is non-trivial (~10 MB of work to
//! load roots), so callers should cache the returned `Arc`.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::Arc;

/// Construct a fresh `ClientConfig` backed by the Mozilla CA bundle from
/// `webpki-roots`. Suitable for both Electrum (TLS-wrapped JSON-RPC) and
/// outbound HTTPS clients.
pub fn tls_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Insecure variant — accepts any server certificate. Safe for Electrum
/// because the daemon validates all returned UTXOs by decoding their
/// CashTokens commits against the manifest-pinned locking bytecode +
/// version bytes; a malicious Fulcrum can at worst stall cycles, never
/// trick the daemon into a wrong-commit broadcast.
///
/// Enabled via `TICKER_ELECTRUM_INSECURE_SKIP_VERIFY=1`. Logged at startup
/// with a WARN-level reminder so the env var can't go silently unnoticed.
pub fn tls_client_config_no_verify() -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    Arc::new(config)
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Picks the TLS config based on `TICKER_ELECTRUM_INSECURE_SKIP_VERIFY` env var.
pub fn tls_client_config_from_env() -> Arc<ClientConfig> {
    if std::env::var("TICKER_ELECTRUM_INSECURE_SKIP_VERIFY").as_deref() == Ok("1") {
        eprintln!("WARN: TICKER_ELECTRUM_INSECURE_SKIP_VERIFY=1 — TLS cert verification disabled");
        tls_client_config_no_verify()
    } else {
        tls_client_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_constructs() {
        let _ = tls_client_config();
    }

    #[test]
    fn no_verify_config_constructs() {
        let _ = tls_client_config_no_verify();
    }
}
