//! Thin cdylib wrapper around `ens-core`.
//!
//! All API is implemented in the `ens-core` sibling crate; this crate
//! exists solely to produce the FFI-exposed dynamic library (`cdylib`) with
//! the UniFFI scaffolding compiled in.

use std::net::SocketAddr;

pub use ens_core::*;

uniffi::include_scaffolding!("ens");

impl UniffiCustomTypeConverter for SocketAddr {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(val.parse().map_err(|e| EnsError::InvalidInput {
            reason: format!("Invalid IpAddr address: '{val}': {e}"),
        })?)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

impl UniffiCustomTypeConverter for HiddenString {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Hidden(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.clone()
    }
}

impl UniffiCustomTypeConverter for HiddenBytes {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Hidden(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.clone()
    }
}
