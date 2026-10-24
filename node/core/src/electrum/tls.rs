//! Rustls client config for Electrum: Mozilla roots, or accept-any for operators who run their
//! own Fulcrum with a self-signed certificate.
//!
//! Threat model: Fulcrum is not trusted for correctness. Every UTXO it returns is decoded
//! against the manifest's locks, category and commitment codec before anything is built from
//! it, and every transaction we broadcast is self-validating on chain. A hostile Fulcrum can
//! stall the operator, not corrupt it.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::sync::Arc;

pub fn tls_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

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
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// `TICKER_ELECTRUM_ACCEPT_ANY_CERT=1` selects the accept-any verifier (logged loudly).
pub fn tls_client_config_from_env() -> Arc<ClientConfig> {
    if std::env::var("TICKER_ELECTRUM_ACCEPT_ANY_CERT").as_deref() == Ok("1") {
        eprintln!("WARN: TICKER_ELECTRUM_ACCEPT_ANY_CERT=1 — Electrum TLS certificate verification skipped");
        tls_client_config_no_verify()
    } else {
        tls_client_config()
    }
}
