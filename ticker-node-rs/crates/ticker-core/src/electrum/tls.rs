//! Rustls client config — Mozilla CA bundle, TLS 1.2/1.3, ring backend.
//!
//! Built once per process and shared between Electrum, the CEX HTTPS fetchers,
//! and any future TLS clients. Construction is non-trivial (~10 MB of work to
//! load roots), so callers should cache the returned `Arc`.

use rustls::ClientConfig;
use rustls::RootCertStore;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_constructs() {
        let _ = tls_client_config();
    }
}
