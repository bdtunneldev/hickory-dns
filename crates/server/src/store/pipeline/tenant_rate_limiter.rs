// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! Per-tenant fixed-window rate limiter (RouteDNS `tenant-rate-limiter`).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use tracing::debug;

#[cfg(all(feature = "metrics", feature = "pipeline"))]
use crate::metrics::pipeline::TenantRateLimiterMetrics;

use crate::{
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, RecordType},
    },
    server::RequestInfo,
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};

/// Configuration for a per-tenant rate limiter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRateLimiterConfig {
    /// Maximum requests per tenant per window.
    #[serde(default = "default_requests")]
    pub requests: u32,
    /// Window size in seconds.
    #[serde(default = "default_window")]
    pub window: u64,
}

fn default_requests() -> u32 {
    400
}
fn default_window() -> u64 {
    60
}

struct CounterState {
    window_id: u64,
    counts: HashMap<String, u32>,
}

/// Fixed-window per-tenant rate limiter using PPv2 TLV 0xE1 tenant id.
pub struct TenantRateLimiterZoneHandler {
    origin: LowerName,
    config: TenantRateLimiterConfig,
    state: Arc<Mutex<CounterState>>,
    #[cfg(all(feature = "metrics", feature = "pipeline"))]
    metrics: TenantRateLimiterMetrics,
}

impl TenantRateLimiterZoneHandler {
    /// Create a tenant rate limiter from configuration.
    pub fn try_from_config(origin: Name, config: TenantRateLimiterConfig) -> Result<Self, String> {
        Ok(Self {
            origin: origin.into(),
            config,
            state: Arc::new(Mutex::new(CounterState {
                window_id: 0,
                counts: HashMap::new(),
            })),
            #[cfg(all(feature = "metrics", feature = "pipeline"))]
            metrics: TenantRateLimiterMetrics::new(),
        })
    }

    fn check(&self, tenant_id: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_id = now / self.config.window.max(1);

        let mut state = self
            .state
            .lock()
            .expect("tenant rate limiter lock poisoned");
        if state.window_id != window_id {
            state.window_id = window_id;
            state.counts.clear();
        }

        let count = state.counts.entry(tenant_id.to_string()).or_insert(0);
        if *count >= self.config.requests {
            return false;
        }
        *count += 1;
        true
    }
}

#[async_trait::async_trait]
impl ZoneHandler for TenantRateLimiterZoneHandler {
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
        _name: &LowerName,
        _rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let Some(info) = request_info else {
            return LookupControlFlow::Skip;
        };

        let Some(tenant_id) = info.tenant_id.as_deref() else {
            // No tenant id — pass through (RouteDNS behavior).
            return LookupControlFlow::Skip;
        };

        if self.check(tenant_id) {
            LookupControlFlow::Skip
        } else {
            debug!(%tenant_id, "tenant rate limit exceeded");
            #[cfg(all(feature = "metrics", feature = "pipeline"))]
            self.metrics.rejected.increment(1);
            LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused)))
        }
    }

    fn metrics_label(&self) -> &'static str {
        "tenant_rate_limiter"
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
