#[derive(Debug)]
pub enum PEMError {
    Io(std::io::Error),
    Base64DecodeError(base64::DecodeError),

    InvalidBlockBound { bound: String, kind: String },
}

pub type PEMResult<T> = Result<T, PEMError>;

impl From<std::io::Error> for PEMError {
    fn from(error: std::io::Error) -> Self {
        PEMError::Io(error)
    }
}

impl From<base64::DecodeError> for PEMError {
    fn from(error: base64::DecodeError) -> Self {
        PEMError::Base64DecodeError(error)
    }
}
