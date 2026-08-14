use std::time::Duration;

use log::debug;
use parking_lot::RwLock;

use crate::{EnsError, Result};

static RUNTIME: RwLock<Option<tokio::runtime::Runtime>> = RwLock::new(None);

pub(crate) fn init_runtime() -> Result<()> {
    debug!("Creating a new runtime");
    let mut rt = RUNTIME.write();
    if rt.is_some() {
        return Err(EnsError::InternalError {
            reason: "runtime already initialized".to_owned(),
        });
    }
    *rt = Some(
        // Must be multithreaded because of `task::block_in_place`
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("libens-rt-worker")
            .worker_threads(2)
            .build()
            .map_err(|e| EnsError::InternalError {
                reason: format!("Failed to build tokio runtime: {e}"),
            })?,
    );
    Ok(())
}

pub(crate) fn deinit_runtime() {
    if let Some(old_runtime) = RUNTIME.write().take() {
        debug!("Destroying the runtime");
        old_runtime.shutdown_timeout(Duration::from_secs(1));
    }
}

// The tasks are always aborted before they are awaited, so cancellation is the expected result
pub(crate) fn is_unexpected_task_failure(error: &tokio::task::JoinError) -> bool {
    !error.is_cancelled()
}

pub fn get_runtime() -> Result<tokio::runtime::Handle> {
    if let Some(rt) = &*RUNTIME.read() {
        Ok(rt.handle().clone())
    } else {
        Err(EnsError::NotInitialized {
            reason: "tokio runtime is not created".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cancellation_is_the_only_expected_task_failure() {
        let cancelled = tokio::spawn(std::future::pending::<()>());
        cancelled.abort();
        let cancelled = cancelled.await.unwrap_err();
        assert!(!is_unexpected_task_failure(&cancelled));

        let panicked = tokio::spawn(async { panic!("boom") }).await.unwrap_err();
        assert!(is_unexpected_task_failure(&panicked));
    }
}
