use std::io::{Read, Write};
use std::net::TcpStream;

pub(super) trait TlsStream: Read + Write {
    fn get_ref(&self) -> &TcpStream;
}
