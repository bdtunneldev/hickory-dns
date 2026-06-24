//! SNI route matching: exact hostnames, wildcards, and regex patterns.

use std::collections::HashMap;

use regex::Regex;

use crate::error::{Result, SniProxyError};

const REGEX_PREFIX: &str = "regex:";
const WILDCARD_PREFIX: &str = "*.";

#[derive(Debug, Clone)]
enum RoutePattern {
    Exact(String),
    Wildcard { suffix: String },
    Regex(Regex),
}

#[derive(Debug, Clone)]
struct RouteEntry {
    pattern: RoutePattern,
    backend: String,
}

/// Route table built from TOML `[routes]` and `[backends]`.
#[derive(Debug, Clone)]
pub struct RouteTable {
    routes: Vec<RouteEntry>,
    backends: HashMap<String, String>,
    default_backend: Option<String>,
}

impl RouteTable {
    pub fn from_config(
        routes: &HashMap<String, String>,
        backends: &HashMap<String, String>,
        default_backend: Option<String>,
    ) -> Result<Self> {
        let mut entries = Vec::with_capacity(routes.len());

        for (pattern, backend) in routes {
            if !backends.contains_key(backend) {
                return Err(SniProxyError::Config(format!(
                    "route {pattern:?} references unknown backend {backend:?}"
                )));
            }

            let route_pattern = if let Some(re) = pattern.strip_prefix(REGEX_PREFIX) {
                RoutePattern::Regex(
                    Regex::new(re)
                        .map_err(|e| SniProxyError::Config(format!("invalid regex {re:?}: {e}")))?,
                )
            } else if let Some(suffix) = pattern.strip_prefix(WILDCARD_PREFIX) {
                if suffix.is_empty() {
                    return Err(SniProxyError::Config(format!(
                        "invalid wildcard route {pattern:?}"
                    )));
                }
                RoutePattern::Wildcard {
                    suffix: suffix.to_ascii_lowercase(),
                }
            } else {
                RoutePattern::Exact(pattern.to_ascii_lowercase())
            };

            entries.push(RouteEntry {
                pattern: route_pattern,
                backend: backend.clone(),
            });
        }

        if let Some(ref name) = default_backend {
            if !backends.contains_key(name) {
                return Err(SniProxyError::Config(format!(
                    "default_backend {name:?} is not defined in [backends]"
                )));
            }
        }

        Ok(Self {
            routes: entries,
            backends: backends.clone(),
            default_backend,
        })
    }

    /// Resolve SNI hostname to a backend socket address string (`host:port`).
    pub fn resolve(&self, sni: &str) -> Result<String> {
        let sni = sni.to_ascii_lowercase();

        // 1. Exact match
        for entry in &self.routes {
            if let RoutePattern::Exact(host) = &entry.pattern {
                if host == &sni {
                    return self.backend_addr(&entry.backend);
                }
            }
        }

        // 2. Wildcard — longest suffix wins
        let mut best: Option<(&RouteEntry, usize)> = None;
        for entry in &self.routes {
            if let RoutePattern::Wildcard { suffix } = &entry.pattern {
                if wildcard_matches(&sni, suffix) {
                    let len = suffix.len();
                    if best.map(|(_, l)| len > l).unwrap_or(true) {
                        best = Some((entry, len));
                    }
                }
            }
        }
        if let Some((entry, _)) = best {
            return self.backend_addr(&entry.backend);
        }

        // 3. Regex — first match in config order
        for entry in &self.routes {
            if let RoutePattern::Regex(re) = &entry.pattern {
                if re.is_match(&sni) {
                    return self.backend_addr(&entry.backend);
                }
            }
        }

        // 4. Default backend
        if let Some(name) = &self.default_backend {
            return self.backend_addr(name);
        }

        Err(SniProxyError::NoRoute { sni })
    }

    fn backend_addr(&self, name: &str) -> Result<String> {
        self.backends
            .get(name)
            .cloned()
            .ok_or_else(|| SniProxyError::UnknownBackend {
                backend: name.to_string(),
            })
    }
}

fn wildcard_matches(sni: &str, suffix: &str) -> bool {
    sni == suffix || sni.ends_with(&format!(".{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RouteTable {
        let mut routes = HashMap::new();
        routes.insert("api.example.com".into(), "direct".into());
        routes.insert("login.example.com".into(), "direct".into());
        routes.insert("*.bkash.com".into(), "bd-relay".into());
        routes.insert("*.nagad.com".into(), "bd-relay".into());
        routes.insert("*.google.com".into(), "direct".into());
        routes.insert(
            r"regex:^staging\.[a-z0-9-]+\.example\.com$".into(),
            "staging".into(),
        );

        let mut backends = HashMap::new();
        backends.insert("bd-relay".into(), "10.10.0.1:443".into());
        backends.insert("direct".into(), "8.8.8.8:443".into());
        backends.insert("staging".into(), "10.0.0.50:443".into());

        RouteTable::from_config(&routes, &backends, None).unwrap()
    }

    #[test]
    fn exact_match_api_and_login() {
        let t = table();
        assert_eq!(t.resolve("api.example.com").unwrap(), "8.8.8.8:443");
        assert_eq!(t.resolve("login.example.com").unwrap(), "8.8.8.8:443");
    }

    #[test]
    fn wildcard_bkash_and_google() {
        let t = table();
        assert_eq!(t.resolve("pay.bkash.com").unwrap(), "10.10.0.1:443");
        assert_eq!(t.resolve("api.bkash.com").unwrap(), "10.10.0.1:443");
        assert_eq!(t.resolve("www.google.com").unwrap(), "8.8.8.8:443");
        assert_eq!(t.resolve("dns.google.com").unwrap(), "8.8.8.8:443");
    }

    #[test]
    fn exact_beats_wildcard() {
        let t = table();
        assert_eq!(t.resolve("api.example.com").unwrap(), "8.8.8.8:443");
    }

    #[test]
    fn regex_route() {
        let t = table();
        assert_eq!(
            t.resolve("staging.app.example.com").unwrap(),
            "10.0.0.50:443"
        );
    }

    #[test]
    fn no_route_errors() {
        let t = table();
        assert!(matches!(
            t.resolve("unknown.test"),
            Err(SniProxyError::NoRoute { .. })
        ));
    }
}
