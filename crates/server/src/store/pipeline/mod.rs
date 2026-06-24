// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! RouteDNS-style pipeline middleware for Hickory DNS zone handler chains.

#![cfg(feature = "pipeline")]

mod common;
mod fastest;
mod rate_limiter;
mod router;
mod split;
mod tenant_rate_limiter;
mod ttl_modifier;

pub use fastest::{FastestConfig, FastestZoneHandler};
pub use rate_limiter::{RateLimiterConfig, RateLimiterZoneHandler};
pub use router::{RouteConfig, RouterConfig, RouterZoneHandler};
pub use split::{BlocklistSource, SplitConfig, SplitZoneHandler};
pub use tenant_rate_limiter::{TenantRateLimiterConfig, TenantRateLimiterZoneHandler};
pub use ttl_modifier::{TtlModifierConfig, TtlModifierZoneHandler};
