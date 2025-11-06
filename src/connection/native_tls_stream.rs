//! TLS connection handling functionality when using the `native-tls` crate for
//! handling TLS.

use native_tls::{TlsConnector, TlsStream};
use std::io::{self};
use std::net::TcpStream;

use crate::Error;

use super::tls::TlsStream as TlsStreamTrait;
use super::Connection;

impl TlsStreamTrait for TlsStream<TcpStream> {
    fn get_ref(&self) -> &TcpStream {
        self.get_ref()
    }
}

pub(super) fn create_stream(
    conn: &Connection,
    tcp: TcpStream,
) -> Result<impl TlsStreamTrait, Error> {
    // native-tls setup
    #[cfg(feature = "log")]
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name = &conn.request.url.host;
    let sess = TlsConnector::new()
        .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))?;

    // Establish TLS session
    #[cfg(feature = "log")]
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    sess.connect(dns_name, tcp)
        .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))
}
