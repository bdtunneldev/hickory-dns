// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! Domain-list split routing (RouteDNS `blocklist-v2` split / bd-split).

use std::{
    collections::HashSet,
    io::{self, Read},
    path::Path,
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[cfg(feature = "metrics")]
use crate::metrics::remote_list;

use crate::{
    net::runtime::TokioRuntimeProvider,
    proto::rr::{LowerName, Name, RecordType},
    server::RequestInfo,
    store::forwarder::{ForwardConfig, ForwardZoneHandler},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupOptions, ZoneHandler, ZoneType,
    },
};

/// A remote or local blocklist source.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistSource {
    /// Source URL or local file path relative to zone directory.
    pub source: String,
    /// Refresh interval in seconds (0 = load once at startup).
    #[serde(default)]
    pub refresh: u64,
    /// Allow fetch failures without failing startup.
    #[serde(default = "default_allow_failure")]
    pub allow_failure: bool,
}

fn default_allow_failure() -> bool {
    true
}

/// Split routing configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitConfig {
    /// Domain list sources (files or HTTP URLs).
    pub blocklist_source: Vec<BlocklistSource>,
    /// Forwarder used when query name matches the domain list.
    pub match_forward: ForwardConfig,
    /// Refresh interval for all sources (seconds).
    #[serde(default = "default_refresh")]
    pub blocklist_refresh: u64,
}

fn default_refresh() -> u64 {
    3600
}

/// Routes matching domains to a dedicated forwarder; non-matches pass to next handler.
pub struct SplitZoneHandler {
    origin: LowerName,
    domains: Arc<RwLock<HashSet<LowerName>>>,
    match_handler: ForwardZoneHandler<TokioRuntimeProvider>,
    sources: Vec<BlocklistSource>,
    refresh: u64,
    zone_dir: PathBuf,
}

use std::path::PathBuf;

impl SplitZoneHandler {
    /// Build a split handler, loading domain lists from configured sources.
    pub async fn try_from_config(
        origin: Name,
        config: SplitConfig,
        zone_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let zone_dir = zone_dir
            .map(Path::to_path_buf)
            .ok_or_else(|| "split handler requires a zone directory".to_string())?;

        let domains = Arc::new(RwLock::new(HashSet::new()));
        let sources = config.blocklist_source.clone();
        let refresh = config.blocklist_refresh;

        Self::reload_domains(&domains, &sources, &zone_dir).await?;

        let match_handler = ForwardZoneHandler::builder_tokio(config.match_forward)
            .with_origin(origin.clone())
            .build()?;

        let handler = Self {
            origin: origin.into(),
            domains,
            match_handler,
            sources,
            refresh,
            zone_dir,
        };

        if handler.refresh > 0 {
            handler.spawn_refresh_task();
        }

        Ok(handler)
    }

    fn spawn_refresh_task(&self) {
        let domains = Arc::clone(&self.domains);
        let sources = self.sources.clone();
        let zone_dir = self.zone_dir.clone();
        let refresh = self.refresh;

        tokio::spawn(async move {
            let interval = Duration::from_secs(refresh);
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = Self::reload_domains(&domains, &sources, &zone_dir).await {
                    warn!("split blocklist refresh failed: {e}");
                    #[cfg(feature = "metrics")]
                    remote_list::record_refresh("split", "all", false);
                }
            }
        });
    }

    async fn reload_domains(
        domains: &Arc<RwLock<HashSet<LowerName>>>,
        sources: &[BlocklistSource],
        zone_dir: &Path,
    ) -> Result<(), String> {
        let mut set = HashSet::new();
        for source in sources {
            let content = match load_source(source, zone_dir).await {
                Ok(content) => {
                    #[cfg(feature = "metrics")]
                    remote_list::record_refresh("split", &source.source, true);
                    content
                }
                Err(e) if source.allow_failure => {
                    warn!("split source {} failed: {e}", source.source);
                    #[cfg(feature = "metrics")]
                    remote_list::record_refresh("split", &source.source, false);
                    continue;
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    remote_list::record_refresh("split", &source.source, false);
                    return Err(e);
                }
            };
            for line in content.lines() {
                let line = line.split('#').next().unwrap_or(line).trim();
                if line.is_empty() {
                    continue;
                }
                let domain = line.trim_start_matches('.');
                if let Ok(mut name) = Name::from_ascii(domain) {
                    name.set_fqdn(true);
                    set.insert(name.into());
                }
            }
        }
        info!("split handler loaded {} domains", set.len());
        *domains.write().await = set;
        Ok(())
    }

    fn name_matches(&self, name: &LowerName, domains: &HashSet<LowerName>) -> bool {
        let mut current = name.clone();
        loop {
            if domains.contains(&current) {
                return true;
            }
            if current.is_root() {
                return false;
            }
            current = current.base_name();
        }
    }
}

async fn load_source(source: &BlocklistSource, zone_dir: &Path) -> Result<String, String> {
    if source.source.starts_with("http://") || source.source.starts_with("https://") {
        #[cfg(feature = "remote-blocklist")]
        {
            let response = reqwest::get(&source.source)
                .await
                .map_err(|e| format!("HTTP fetch failed for {}: {e}", source.source))?;
            if !response.status().is_success() {
                if source.allow_failure {
                    warn!(
                        "HTTP fetch returned {} for {}",
                        response.status(),
                        source.source
                    );
                    return Ok(String::new());
                }
                return Err(format!(
                    "HTTP fetch returned {} for {}",
                    response.status(),
                    source.source
                ));
            }
            response
                .text()
                .await
                .map_err(|e| format!("HTTP read failed for {}: {e}", source.source))
        }
        #[cfg(not(feature = "remote-blocklist"))]
        {
            let _ = source;
            Err("remote blocklist sources require the remote-blocklist feature".to_string())
        }
    } else {
        let path = zone_dir.join(&source.source);
        let mut file = std::fs::File::open(&path)
            .map_err(|e| format!("unable to open {}: {e}", path.display()))?;
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e: io::Error| format!("unable to read {}: {e}", path.display()))?;
        Ok(content)
    }
}

#[async_trait::async_trait]
impl ZoneHandler for SplitZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let domains = self.domains.read().await;
        if self.name_matches(name, &domains) {
            self.match_handler
                .lookup(name, rtype, request_info, lookup_options)
                .await
        } else {
            LookupControlFlow::Skip
        }
    }

    fn metrics_label(&self) -> &'static str {
        "split"
    }

    async fn nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        super::common::unimplemented_nsec(name, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    async fn nsec3_records(
        &self,
        info: crate::zone_handler::Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        super::common::unimplemented_nsec3(info, lookup_options).await
    }

    #[cfg(feature = "__dnssec")]
    fn nx_proof_kind(&self) -> Option<&crate::dnssec::NxProofKind> {
        None
    }
}
