use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::error::PEMError;
use crate::reader::PEMReader;

const CERTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/certs");

fn path(name: &str) -> String {
    format!("{CERTS}/{name}")
}

#[test]
fn reads_server_certificate() {
    let mut reader = PEMReader::new(path("server.crt")).unwrap();
    let expected = CertificateDer::from_pem_file(path("server.crt")).unwrap();

    assert_eq!(reader.next_certificate().unwrap(), Some(expected));
    assert_eq!(reader.next_certificate().unwrap(), None);
}

#[test]
fn reads_ca_certificate() {
    let mut reader = PEMReader::new(path("ca.crt")).unwrap();
    let expected = CertificateDer::from_pem_file(path("ca.crt")).unwrap();

    assert_eq!(reader.next_certificate().unwrap(), Some(expected));
    assert_eq!(reader.next_certificate().unwrap(), None);
}

#[test]
fn skips_private_key() {
    let mut reader = PEMReader::new(path("server.key")).unwrap();

    assert_eq!(reader.next_certificate().unwrap(), None);
}

#[test]
fn missing_file_is_io_error() {
    let result = PEMReader::new(path("does-not-exist.crt"));

    assert!(matches!(result, Err(PEMError::Io(_))));
}

#[test]
fn reads_private_key() {
    let mut reader = PEMReader::new(path("server.key")).unwrap();
    let expected = PrivateKeyDer::from_pem_file(path("server.key")).unwrap();

    assert_eq!(reader.next_private_key().unwrap(), Some(expected));
    assert_eq!(reader.next_private_key().unwrap(), None);
}

#[test]
fn reads_ca_private_key() {
    let mut reader = PEMReader::new(path("ca.key")).unwrap();
    let expected = PrivateKeyDer::from_pem_file(path("ca.key")).unwrap();

    assert_eq!(reader.next_private_key().unwrap(), Some(expected));
    assert_eq!(reader.next_private_key().unwrap(), None);
}

#[test]
fn skips_certificate() {
    let mut reader = PEMReader::new(path("server.crt")).unwrap();

    assert_eq!(reader.next_private_key().unwrap(), None);
}
