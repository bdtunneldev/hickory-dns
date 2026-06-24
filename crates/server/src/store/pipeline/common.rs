// Copyright 2026 RAHMAT AL ZAMI
//
// Shared helpers for pipeline zone handlers.

use std::io;

use crate::{
    proto::rr::LowerName,
    zone_handler::{AuthLookup, LookupControlFlow, LookupError, LookupOptions},
};

/// Default NSEC response for pipeline middleware handlers.
pub(super) async fn unimplemented_nsec(
    _name: &LowerName,
    _lookup_options: LookupOptions,
) -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
        "NSEC records are unimplemented for pipeline handlers",
    ))))
}

/// Default NSEC3 response for pipeline middleware handlers.
#[cfg(feature = "__dnssec")]
pub(super) async fn unimplemented_nsec3(
    _info: crate::zone_handler::Nsec3QueryInfo<'_>,
    _lookup_options: LookupOptions,
) -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
        "NSEC3 records are unimplemented for pipeline handlers",
    ))))
}
