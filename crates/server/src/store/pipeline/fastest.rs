// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! Race multiple upstream forwarders (RouteDNS `fastest`).

use std::sync::Arc;

use futures_util::future::select_all;
use serde::Deserialize;
use tracing::debug;

#[cfg(all(feature = "metrics", feature = "pipeline"))]
use crate::metrics::pipeline::FastestMetrics;

use crate::{
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::ResponseCode,
        rr::{LowerName, Name, RecordType},
    },
    server::RequestInfo,
    store::forwarder::{ForwardConfig, ForwardZoneHandler},
    zone_handler::{
        AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler,
        ZoneType,
    },
};

/// Configuration for fastest-resolver racing.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastestConfig {
    /// Forwarder configurations to race.
    pub forwards: Vec<ForwardConfig>,
}

/// Races multiple forwarders and returns the first successful response.
pub struct FastestZoneHandler {
    origin: LowerName,
    handlers: Vec<Arc<ForwardZoneHandler<TokioRuntimeProvider>>>,
    #[cfg(all(feature = "metrics", feature = "pipeline"))]
    metrics: FastestMetrics,
}

impl FastestZoneHandler {
    /// Build a fastest handler from configuration.
    pub fn try_from_config(origin: Name, config: FastestConfig) -> Result<Self, String> {
        if config.forwards.is_empty() {
            return Err("fastest requires at least one forward configuration".to_string());
        }

        let handlers = config
            .forwards
            .into_iter()
            .map(|fwd| {
                ForwardZoneHandler::builder_tokio(fwd)
                    .with_origin(origin.clone())
                    .build()
                    .map(Arc::new)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            origin: origin.into(),
            handlers,
            #[cfg(all(feature = "metrics", feature = "pipeline"))]
            metrics: FastestMetrics::new(),
        })
    }
}

#[async_trait::async_trait]
impl ZoneHandler for FastestZoneHandler {
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
        let name = name.clone();
        let mut futures: Vec<
            std::pin::Pin<
                Box<dyn std::future::Future<Output = LookupControlFlow<AuthLookup>> + Send>,
            >,
        > = Vec::with_capacity(self.handlers.len());
        for handler in &self.handlers {
            let handler = Arc::clone(handler);
            let name = name.clone();
            let request_info = request_info.cloned();
            futures.push(Box::pin(async move {
                handler
                    .lookup(&name, rtype, request_info.as_ref(), lookup_options)
                    .await
            }));
        }

        let mut last_err =
            LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::ServFail)));

        while !futures.is_empty() {
            let (result, _idx, remaining) = select_all(futures).await;
            futures = remaining;
            match result {
                LookupControlFlow::Continue(Ok(lookup)) | LookupControlFlow::Break(Ok(lookup)) => {
                    debug!("fastest: upstream returned success");
                    return LookupControlFlow::Continue(Ok(lookup));
                }
                LookupControlFlow::Continue(Err(e)) | LookupControlFlow::Break(Err(e)) => {
                    #[cfg(all(feature = "metrics", feature = "pipeline"))]
                    self.metrics.upstream_errors.increment(1);
                    last_err = LookupControlFlow::Continue(Err(e));
                }
                LookupControlFlow::Skip => {}
            }
        }

        last_err
    }

    fn metrics_label(&self) -> &'static str {
        "fastest"
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
