//! TLS connection handling functionality when using the `rustls` crate for
//! handling TLS.

use crate::Error;
use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{self};
use std::net::TcpStream;
use std::sync::Arc;
#[cfg(feature = "rustls-webpki")]
use webpki_roots::TLS_SERVER_ROOTS;

use super::tls::TlsStream as TlsStreamTrait;
use super::Connection;

impl TlsStreamTrait for StreamOwned<ClientConnection, TcpStream> {
    fn get_ref(&self) -> &TcpStream {
        self.get_ref()
    }
}

static CONFIG: std::sync::LazyLock<Arc<ClientConfig>> = std::sync::LazyLock::new(|| {
    let mut root_certificates = RootCertStore::empty();

    // Try to load native certs
    #[cfg(feature = "https-rustls-probe")]
    if let Ok(os_roots) = rustls_native_certs::load_native_certs() {
        for root_cert in os_roots {
            // Ignore erroneous OS certificates, there's nothing
            // to do differently in that situation anyways.
            let _ = root_certificates.add(root_cert);
        }
    }

    #[cfg(feature = "rustls-webpki")]
    root_certificates.extend(TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_certificates)
        .with_no_client_auth();
    Arc::new(config)
});

pub(super) fn create_stream(
    conn: &Connection,
    tcp: TcpStream,
) -> Result<impl TlsStreamTrait, Error> {
    // Rustls setup
    #[cfg(feature = "log")]
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name = ServerName::try_from(conn.request.url.host.as_str())
        .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))?;
    let sess = ClientConnection::new(CONFIG.clone(), dns_name).map_err(Error::TlsError)?;

    // Establish TLS session
    #[cfg(feature = "log")]
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    Ok(StreamOwned::new(sess, tcp))
}