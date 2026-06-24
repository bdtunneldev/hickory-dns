// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! Per-client-IP fixed-window rate limiter (RouteDNS `rate-limiter`).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use tracing::debug;

#[cfg(all(feature = "metrics", feature = "pipeline"))]
use crate::metrics::pipeline::RateLimiterMetrics;

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

/// Configuration for a per-IP rate limiter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimiterConfig {
    /// Maximum requests allowed per window per client IP.
    #[serde(default = "default_requests")]
    pub requests: u32,
    /// Window size in seconds.
    #[serde(default = "default_window")]
    pub window: u64,
    /// IPv4 prefix length for bucketing (default /32).
    #[serde(default = "default_prefix4")]
    pub prefix4: u8,
    /// IPv6 prefix length for bucketing (default /128).
    #[serde(default = "default_prefix6")]
    pub prefix6: u8,
}

fn default_requests() -> u32 {
    500
}
fn default_window() -> u64 {
    60
}
fn default_prefix4() -> u8 {
    32
}
fn default_prefix6() -> u8 {
    128
}

struct CounterState {
    window_id: u64,
    counts: HashMap<IpAddr, u32>,
}

/// Fixed-window per-IP rate limiter zone handler.
///
/// Returns `Skip` when under the limit (pass to next handler in chain).
/// Returns `Break(Refused)` when the limit is exceeded.
pub struct RateLimiterZoneHandler {
    origin: LowerName,
    config: RateLimiterConfig,
    state: Arc<Mutex<CounterState>>,
    #[cfg(all(feature = "metrics", feature = "pipeline"))]
    metrics: RateLimiterMetrics,
}

impl RateLimiterZoneHandler {
    /// Create a rate limiter from configuration.
    pub fn try_from_config(origin: Name, config: RateLimiterConfig) -> Result<Self, String> {
        Ok(Self {
            origin: origin.into(),
            config,
            state: Arc::new(Mutex::new(CounterState {
                window_id: 0,
                counts: HashMap::new(),
            })),
            #[cfg(all(feature = "metrics", feature = "pipeline"))]
            metrics: RateLimiterMetrics::new(),
        })
    }

    fn masked_ip(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let mask = if self.config.prefix4 >= 32 {
                    !0u32
                } else {
                    !0u32 << (32 - self.config.prefix4)
                };
                let octets = u32::from(v4) & mask;
                IpAddr::V4(Ipv4Addr::from(octets.to_be_bytes()))
            }
            IpAddr::V6(v6) => {
                let mask_bits = self.config.prefix6.min(128);
                let mut octets = v6.octets();
                let full_bytes = (mask_bits / 8) as usize;
                let rem_bits = mask_bits % 8;
                for b in octets.iter_mut().skip(full_bytes) {
                    *b = 0;
                }
                if rem_bits > 0 && full_bytes < 16 {
                    let mask = 0xFFu8 << (8 - rem_bits);
                    octets[full_bytes] &= mask;
                }
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        }
    }

    fn check(&self, ip: IpAddr) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_id = now / self.config.window.max(1);
        let key = self.masked_ip(ip);

        let mut state = self.state.lock().expect("rate limiter lock poisoned");
        if state.window_id != window_id {
            state.window_id = window_id;
            state.counts.clear();
        }

        let count = state.counts.entry(key).or_insert(0);
        if *count >= self.config.requests {
            return false;
        }
        *count += 1;
        true
    }
}

use std::net::{Ipv4Addr, Ipv6Addr};

#[async_trait::async_trait]
impl ZoneHandler for RateLimiterZoneHandler {
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

        if self.check(info.src.ip()) {
            LookupControlFlow::Skip
        } else {
            debug!(ip = %info.src.ip(), "rate limit exceeded");
            #[cfg(all(feature = "metrics", feature = "pipeline"))]
            self.metrics.rejected.increment(1);
            LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused)))
        }
    }

    fn metrics_label(&self) -> &'static str {
        "rate_limiter"
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

#[cfg(all(test, feature = "pipeline"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    use hickory_proto::op::{LowerQuery, MessageType, Metadata, OpCode, Query};
    use hickory_proto::rr::{LowerName, Name, RecordType};

    use super::*;
    use crate::net::xfer::Protocol;
    use crate::server::RequestInfo;
    use crate::zone_handler::{LookupControlFlow, LookupOptions, ZoneHandler};

    fn request_info(ip: Ipv4Addr) -> RequestInfo<'static> {
        let query = Query::new(Name::from_str("example.com.").unwrap(), RecordType::A);
        let metadata = Box::leak(Box::new(Metadata::new(
            1,
            MessageType::Query,
            OpCode::Query,
        )));
        let lower_query = Box::leak(Box::new(LowerQuery::from(query)));
        RequestInfo::new(
            SocketAddr::new(IpAddr::V4(ip), 12345),
            Protocol::Tcp,
            metadata,
            lower_query,
        )
    }

    #[tokio::test]
    async fn rate_limiter_allows_then_refuses() {
        let handler = RateLimiterZoneHandler::try_from_config(
            Name::root(),
            RateLimiterConfig {
                requests: 2,
                window: 60,
                prefix4: 32,
                prefix6: 128,
            },
        )
        .unwrap();

        let info = request_info(Ipv4Addr::new(203, 0, 113, 50));
        let name = LowerName::from(Name::from_str("example.com.").unwrap());

        for _ in 0..2 {
            match handler
                .lookup(&name, RecordType::A, Some(&info), LookupOptions::default())
                .await
            {
                LookupControlFlow::Skip => {}
                _ => panic!("expected skip under limit"),
            }
        }

        match handler
            .lookup(&name, RecordType::A, Some(&info), LookupOptions::default())
            .await
        {
            LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::Refused))) => {}
            _ => panic!("expected refused over limit"),
        }
    }
}
