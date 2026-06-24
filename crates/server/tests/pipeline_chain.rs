//! Integration tests for the RouteDNS-style pipeline chain.

#![cfg(all(feature = "pipeline", feature = "blocklist", feature = "resolver"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::op::{LowerQuery, MessageType, Metadata, OpCode, Query};
use hickory_proto::rr::{LowerName, Name, RecordType};
use hickory_server::net::xfer::Protocol;
use hickory_server::server::RequestInfo;
use hickory_server::store::blocklist::{BlocklistConfig, BlocklistZoneHandler};
use hickory_server::store::pipeline::{RateLimiterConfig, RateLimiterZoneHandler};
use hickory_server::zone_handler::{LookupControlFlow, LookupOptions, ZoneHandler};

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
async fn pipeline_rate_limiter_then_blocklist() {
    let rate_limiter = RateLimiterZoneHandler::try_from_config(
        Name::root(),
        RateLimiterConfig {
            requests: 100,
            window: 60,
            prefix4: 32,
            prefix6: 128,
        },
    )
    .unwrap();

    let zone_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/test-data/test_configs");
    let blocklist = BlocklistZoneHandler::try_from_config(
        Name::root(),
        BlocklistConfig {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec!["default/blocklist.txt".to_string()],
            ..BlocklistConfig::default()
        },
        Some(zone_dir.as_path()),
    )
    .unwrap();

    let handlers: Vec<Arc<dyn ZoneHandler>> = vec![Arc::new(rate_limiter), Arc::new(blocklist)];
    let name = LowerName::from(Name::from_str("example.com.").unwrap());
    let info = request_info(Ipv4Addr::new(203, 0, 113, 99));

    let mut flow = LookupControlFlow::Skip;
    for handler in &handlers {
        if matches!(flow, LookupControlFlow::Skip) {
            flow = handler
                .lookup(&name, RecordType::A, Some(&info), LookupOptions::default())
                .await;
        }
    }

    assert!(
        matches!(flow, LookupControlFlow::Break(Ok(_))),
        "expected blocklist break with answer"
    );
}

#[tokio::test]
async fn pipeline_rate_limiter_refuses_before_blocklist() {
    let rate_limiter = RateLimiterZoneHandler::try_from_config(
        Name::root(),
        RateLimiterConfig {
            requests: 1,
            window: 60,
            prefix4: 32,
            prefix6: 128,
        },
    )
    .unwrap();

    let zone_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/test-data/test_configs");
    let blocklist = BlocklistZoneHandler::try_from_config(
        Name::root(),
        BlocklistConfig {
            wildcard_match: true,
            min_wildcard_depth: 2,
            lists: vec!["default/blocklist.txt".to_string()],
            ..BlocklistConfig::default()
        },
        Some(zone_dir.as_path()),
    )
    .unwrap();

    let handlers: Vec<Arc<dyn ZoneHandler>> = vec![Arc::new(rate_limiter), Arc::new(blocklist)];
    let name = LowerName::from(Name::from_str("example.com.").unwrap());
    let info = request_info(Ipv4Addr::new(203, 0, 113, 1));

    let mut flow = LookupControlFlow::Skip;
    for handler in &handlers {
        if matches!(flow, LookupControlFlow::Skip) {
            flow = handler
                .lookup(&name, RecordType::A, Some(&info), LookupOptions::default())
                .await;
        }
    }
    assert!(matches!(flow, LookupControlFlow::Break(Ok(_))));

    flow = LookupControlFlow::Skip;
    for handler in &handlers {
        if matches!(flow, LookupControlFlow::Skip) {
            flow = handler
                .lookup(&name, RecordType::A, Some(&info), LookupOptions::default())
                .await;
        }
    }

    assert!(
        matches!(
            flow,
            LookupControlFlow::Break(Err(
                hickory_server::zone_handler::LookupError::ResponseCode(
                    hickory_proto::op::ResponseCode::Refused
                )
            ))
        ),
        "expected rate limit refused"
    );
}
