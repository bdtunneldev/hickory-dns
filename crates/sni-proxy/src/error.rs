use std::net::AddrParseError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SniProxyError {
    #[error("failed to parse configuration: {0}")]
    Config(String),

    #[error("TLS ClientHello parse error: {0}")]
    ClientHello(String),

    #[error("no SNI hostname in ClientHello")]
    NoSni,

    #[error("no route matched SNI {sni:?}")]
    NoRoute { sni: String },

    #[error("unknown backend {backend:?}")]
    UnknownBackend { backend: String },

    #[error("invalid backend address {address:?}: {source}")]
    InvalidBackend {
        address: String,
        #[source]
        source: AddrParseError,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SniProxyError>;
