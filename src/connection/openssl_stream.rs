//! TLS connection handling functionality when using the `openssl` crate for
//! handling TLS.
//!
//! This module is based on how native-tls handles setting up OpenSSL
//! connections. The original native-tls code was provided under the following
//! license:
//!
//! > Copyright (c) 2016 The rust-native-tls Developers
//! >
//! > Permission is hereby granted, free of charge, to any person obtaining a
//! > copy of this software and associated documentation files (the "Software"),
//! > to deal in the Software without restriction, including without limitation
//! > the rights to use, copy, modify, merge, publish, distribute, sublicense,
//! > and/or sell copies of the Software, and to permit persons to whom the
//! > Software is furnished to do so, subject to the following conditions:
//! >
//! > The above copyright notice and this permission notice shall be included in
//! > all copies or substantial portions of the Software.
//! >
//! > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//! > THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//! > FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! > DEALINGS IN THE SOFTWARE.

use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVersion};
use openssl::x509::X509;
use std::fs;
use std::io::{self};
use std::net::TcpStream;

use crate::Error;

use super::tls::TlsStream as TlsStreamTrait;
use super::Connection;

impl TlsStreamTrait for SslStream<TcpStream> {
    fn get_ref(&self) -> &TcpStream {
        self.get_ref()
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::IoError(io::Error::new(io::ErrorKind::Other, err))
    }
}

pub(super) fn create_stream(
    conn: &Connection,
    tcp: TcpStream,
) -> Result<impl TlsStreamTrait, Error> {
    // openssl setup
    #[cfg(feature = "log")]
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let connector = {
        let mut connector_builder = SslConnector::builder(SslMethod::tls())?;
        connector_builder.set_min_proto_version(Some(SslVersion::TLS1))?;

        #[cfg(feature = "openssl-probe")]
        {
            let probe = openssl_probe::probe();
            connector_builder
                .load_verify_locations(probe.cert_file.as_deref(), probe.cert_dir.as_deref())?;
        }

        if cfg!(target_os = "android") {
            if let Ok(dir) = fs::read_dir("/system/etc/security/cacerts") {
                let certs = dir
                    .filter_map(|r| r.ok())
                    .filter_map(|e| fs::read(e.path()).ok())
                    .filter_map(|b| X509::from_pem(&b).ok());
                for cert in certs {
                    if let Err(_err) = connector_builder.cert_store_mut().add_cert(cert) {
                        #[cfg(feature = "log")]
                        log::debug!("load_android_root_certs error: {:?}", _err);
                    }
                }
            }
        }

        connector_builder.build().configure()?
    };

    // Establish TLS session
    #[cfg(feature = "log")]
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    connector
        .use_server_name_indication(true)
        .verify_hostname(true)
        .connect(&conn.request.url.host, tcp)
        .map_err(|err| Error::IoError(io::Error::new(io::ErrorKind::Other, err)))
}
