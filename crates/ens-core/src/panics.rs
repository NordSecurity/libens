use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::EnsError;

pub fn catch_panic_result<T, F>(operation: F) -> Result<T, EnsError>
where
    F: FnOnce() -> Result<T, EnsError>,
{
    catch_panic_message(operation).map_err(|reason| EnsError::InternalError { reason })?
}

pub(crate) fn catch_panic_message<T, F>(operation: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(operation)).map_err(|payload| panic_to_message(&*payload))
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
                panic_payload_to_string(&*payload)
            );
            fallback
        }
    }
}

fn panic_to_message(payload: &(dyn std::any::Any + Send)) -> String {
    let reason = panic_payload_to_string(payload);
    log::error!("caught panic across FFI boundary: {reason}");
    reason
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catch_panic_result() {
        let err =
            catch_panic_result(|| -> std::result::Result<u32, _> { panic!("foo") }).unwrap_err();
        assert!(format!("{err:?}").contains("foo"));
    }
}
