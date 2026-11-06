use crate::error::PEMError;
use crate::tokenize::Token;
use crate::tokenize::Kind;

#[test]
fn begin_certificate() {
    assert_eq!(
        Token::parse_line("-----BEGIN CERTIFICATE-----").unwrap(),
        Token::Begin(Kind::Certificate)
    );
}

#[test]
fn end_certificate() {
    assert_eq!(
        Token::parse_line("-----END CERTIFICATE-----").unwrap(),
        Token::End(Kind::Certificate)
    );
}

#[test]
fn begin_private_key() {
    assert_eq!(
        Token::parse_line("-----BEGIN PRIVATE KEY-----").unwrap(),
        Token::Begin(Kind::PrivateKey)
    );
}

#[test]
fn end_private_key() {
    assert_eq!(
        Token::parse_line("-----END PRIVATE KEY-----").unwrap(),
        Token::End(Kind::PrivateKey)
    );
}

#[test]
fn content_line_is_arbitrary() {
    let line = "MIIBszCCAVmgAwIBAgIUQ2xhdWRlVGVzdA==";
    assert_eq!(
        Token::parse_line(line).unwrap(),
        Token::Arbitrary(line.to_string())
    );
}

#[test]
fn empty_line_is_arbitrary() {
    assert_eq!(
        Token::parse_line("").unwrap(),
        Token::Arbitrary(String::new())
    );
}

#[test]
fn unknown_kind_is_invalid() {
    assert!(matches!(
        Token::parse_line("-----BEGIN FOO-----").unwrap_err(),
        PEMError::InvalidBlockBound { bound, kind } if bound == "BEGIN" && kind == "FOO"
    ));
}

#[test]
fn unknown_bound_is_invalid() {
    assert!(matches!(
        Token::parse_line("-----START CERTIFICATE-----").unwrap_err(),
        PEMError::InvalidBlockBound { bound, kind } if bound == "START" && kind == "CERTIFICATE"
    ));
}
