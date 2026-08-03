use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::EnsError;

pub fn catch_panic_result<T, F>(operation: F) -> Result<T, EnsError>
where
    F: FnOnce() -> Result<T, EnsError>,
{
    catch_unwind(AssertUnwindSafe(operation)).map_err(|e| panic_to_error(&e))?
}

pub fn catch_panic<T, F>(operation: F, fallback: T) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(value) => value,
        Err(payload) => {
            log::error!(
                "caught panic across FFI boundary: {}",
                panic_payload_to_string(&payload)
            );
            fallback
        }
    }
}

fn panic_to_error(payload: &(dyn std::any::Any + Send)) -> EnsError {
    let reason = panic_payload_to_string(payload);
    log::error!("caught panic across FFI boundary: {reason}");
    EnsError::InternalError { reason }
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic without message".to_string()
    }
}
