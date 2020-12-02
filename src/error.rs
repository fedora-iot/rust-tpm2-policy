use std::fmt;

#[derive(Debug)]
pub enum Error {
    TPM(tss_esapi::Error),
    NoMatchingPolicy,
    InvalidValue,
    NotImplemented(String),
    IO(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::TPM(err) => {
                write!(f, "TPM error: ")?;
                err.fmt(f)
            }
            Error::NoMatchingPolicy => write!(f, "No matching policy found in policy list"),
            Error::InvalidValue => write!(f, "Invalid parameter value"),
            Error::NotImplemented(value) => write!(f, "Feature {} not implemented", value),
            Error::IO(err) => {
                write!(f, "IO error: ")?;
                err.fmt(f)
            }
        }
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(err: tss_esapi::Error) -> Self {
        Error::TPM(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
