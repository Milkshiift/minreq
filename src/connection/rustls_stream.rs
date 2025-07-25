//! TLS connection handling functionality when using the `rustls` crate for
//! handling TLS.

use rustls::{self, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;
use std::convert::TryFrom;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;
#[cfg(feature = "rustls-webpki")]
use webpki_roots::TLS_SERVER_ROOTS;

use crate::Error;

use super::{Connection, HttpStream};

pub type SecuredStream = StreamOwned<ClientConnection, TcpStream>;

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
    {
        root_certificates.extend(TLS_SERVER_ROOTS.iter().cloned());
    }
    
    let config = ClientConfig::builder()
        .with_root_certificates(root_certificates)
        .with_no_client_auth();
    Arc::new(config)
});

pub fn create_secured_stream(conn: &Connection) -> Result<HttpStream, Error> {
    // Rustls setup
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    
    let dns_name = match ServerName::try_from(conn.request.url.host.clone()) {
        Ok(result) => result,
        Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
    };

    let sess =
        ClientConnection::new(CONFIG.clone(), dns_name).map_err(Error::RustlsCreateConnection)?;

    // Connect
    log::trace!("Establishing TCP connection to {}.", conn.request.url.host);
    let tcp = conn.connect()?;

    // Send request
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    let mut tls = StreamOwned::new(sess, tcp); // I don't think this actually does any communication.
    log::trace!("Writing HTTPS request to {}.", conn.request.url.host);
    let _ = tls.get_ref().set_write_timeout(conn.timeout()?);
    tls.write_all(&conn.request.as_bytes())?;

    Ok(HttpStream::create_secured(tls, conn.timeout_at))
}