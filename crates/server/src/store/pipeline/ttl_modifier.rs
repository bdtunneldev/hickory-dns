// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! TTL clamping middleware (RouteDNS `ttl-modifier`).

use serde::Deserialize;

use crate::{
    proto::rr::{LowerName, Name, RecordType},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupOptions, ZoneHandler, ZoneType,
    },
};

/// TTL modifier configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlModifierConfig {
    /// Minimum TTL for all records in responses.
    #[serde(default)]
    pub ttl_min: u32,
    /// Maximum TTL (0 = no upper limit).
    #[serde(default)]
    pub ttl_max: u32,
}

/// Clamps record TTLs in responses via the consult phase.
///
/// Place this handler after a recursor/forwarder in the zone chain. It does not
/// resolve queries itself — it modifies TTLs on answers from upstream handlers.
pub struct TtlModifierZoneHandler {
    origin: LowerName,
    config: TtlModifierConfig,
}

impl TtlModifierZoneHandler {
    /// Create a TTL modifier from configuration.
    pub fn try_from_config(origin: Name, config: TtlModifierConfig) -> Result<Self, String> {
        Ok(Self {
            origin: origin.into(),
            config,
        })
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        let max = if self.config.ttl_max == 0 {
            u32::MAX
        } else {
            self.config.ttl_max
        };
        ttl.clamp(self.config.ttl_min, max)
    }

    fn modify_lookup(&self, lookup: AuthLookup) -> AuthLookup {
        use crate::proto::rr::Record;
        use crate::zone_handler::LookupRecords;

        let records: Vec<Record> = lookup
            .iter()
            .map(|r| {
                let mut record = r.clone();
                record.ttl = self.clamp_ttl(record.ttl);
                record
            })
            .collect();

        if records.is_empty() {
            lookup
        } else {
            AuthLookup::Records {
                answers: LookupRecords::Section(records),
                additionals: None,
            }
        }
    }
}

#[async_trait::async_trait]
impl ZoneHandler for TtlModifierZoneHandler {
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
        _request_info: Option<&crate::server::RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // TTL modifier only acts in consult phase.
        LookupControlFlow::Skip
    }

    async fn consult(
        &self,
        _name: &LowerName,
        _rtype: RecordType,
        _request_info: Option<&crate::server::RequestInfo<'_>>,
        _lookup_options: LookupOptions,
        last_result: LookupControlFlow<AuthLookup>,
    ) -> (
        LookupControlFlow<AuthLookup>,
        Option<crate::proto::rr::TSigResponseContext>,
    ) {
        match last_result {
            LookupControlFlow::Continue(Ok(lookup)) => (
                LookupControlFlow::Continue(Ok(self.modify_lookup(lookup))),
                None,
            ),
            LookupControlFlow::Break(Ok(lookup)) => (
                LookupControlFlow::Break(Ok(self.modify_lookup(lookup))),
                None,
            ),
            other => (other, None),
        }
    }

    fn metrics_label(&self) -> &'static str {
        "ttl_modifier"
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
