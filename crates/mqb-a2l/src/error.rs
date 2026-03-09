use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unexpected end of file")]
    UnexpectedEof,

    #[error("expected a keyword/word token, got a string")]
    ExpectedWord,

    #[error("expected keyword '{expected}', got '{got}'")]
    UnexpectedKeyword { expected: String, got: String },

    #[error("unknown datatype '{0}'")]
    UnknownDatatype(String),

    #[error("cannot parse '{0}' as float")]
    ParseFloat(String),

    #[error("cannot parse '{0}' as integer")]
    ParseInt(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
