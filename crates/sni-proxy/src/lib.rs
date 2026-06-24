//! TLS SNI passthrough proxy (sniproxy-style routing without termination).
//!
//! Peeks at the TLS `ClientHello`, extracts the SNI hostname, selects a backend
//! from TOML routes, and forwards the raw TLS stream unchanged.

pub mod client_hello;
pub mod config;
pub mod error;
pub mod proxy;
pub mod router;

pub use config::Config;
pub use error::{Result, SniProxyError};
pub use proxy::SniProxyServer;
pub use router::RouteTable;
