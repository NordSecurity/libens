//! Thin cdylib wrapper around `nordtls-core`.
//!
//! All API is implemented in the `nordtls-core` sibling crate; this crate
//! exists solely to produce the FFI-exposed dynamic library (`cdylib`) with
//! the UniFFI scaffolding and the Android JNI entry point compiled in.

use std::net::SocketAddr;

pub use ens_core::*;

uniffi::include_scaffolding!("ens");

impl UniffiCustomTypeConverter for SocketAddr {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(val.parse().map_err(|e| EnsError::InternalError {
            reason: format!("Invalid IpAddr address: '{val}': {e}"),
        })?)
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
/// Initialize OS certificate store, should be called only once. Without call to
/// `Java_com_nordsec_nordtls_NordtlsCert_initCertStore()` quench will not be
/// able to verify https certificates in the system certificate store.
/// # Params
/// - `env`:    see https://developer.android.com/training/articles/perf-jni#javavm-and-jnienv
/// - `ctx`:    see https://developer.android.com/reference/android/content/Context
pub extern "C" fn Java_com_nordsec_nordtls_NordtlsCert_initCertStore(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::objects::JObject,
) -> jni::sys::jint {
    if let Err(err) = rustls_platform_verifier::android::init_hosted(&mut env, ctx) {
        log::error!("Failed to initialize certificate store {err:?}");
        return 1;
    }

    0
}
