use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, SniProxyError};
use crate::router::RouteTable;

/// Top-level TOML configuration for `hickory-sni-proxy`.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address to listen on, e.g. `0.0.0.0:443`.
    pub listen: String,

    /// Named upstream backends (`host:port`).
    #[serde(default)]
    pub backends: HashMap<String, String>,

    /// SNI pattern → backend name.
    #[serde(default)]
    pub routes: HashMap<String, String>,

    /// Backend used when no route matches.
    #[serde(default)]
    pub default_backend: Option<String>,

    /// Milliseconds to wait for a complete ClientHello (default 5000).
    #[serde(default = "default_peek_timeout_ms")]
    pub peek_timeout_ms: u64,
}

fn default_peek_timeout_ms() -> u64 {
    5000
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let text = fs::read_to_string(path.as_ref()).map_err(SniProxyError::Io)?;
        Self::from_str(&text)
    }

    pub fn from_str(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| SniProxyError::Config(e.to_string()))
    }

    pub fn route_table(&self) -> Result<RouteTable> {
        RouteTable::from_config(&self.routes, &self.backends, self.default_backend.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let text = r#"
listen = "0.0.0.0:8443"

[backends]
bd-relay = "10.10.0.1:443"
direct = "8.8.8.8:443"

[routes]
"*.bkash.com" = "bd-relay"
"*.nagad.com" = "bd-relay"
"*.google.com" = "direct"
"api.example.com" = "direct"
"#;
        let cfg = Config::from_str(text).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:8443");
        let table = cfg.route_table().unwrap();
        assert_eq!(table.resolve("pay.bkash.com").unwrap(), "10.10.0.1:443");
    }
}
