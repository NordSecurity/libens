#[path = "../src/test_support/mod.rs"]
mod test_support;

use ens_core::{set_log_callback, LogLevel};

use test_support::RecordedLogCallback;

const FIRST_MESSAGE: &str = "first callback message";
const SECOND_MESSAGE: &str = "second callback message";

#[test]
fn second_set_log_callback_replaces_first() {
    let first = RecordedLogCallback::default();
    set_log_callback(LogLevel::Debug, Box::new(first.clone())).unwrap();

    log::info!("{FIRST_MESSAGE}");
    assert!(first.received(FIRST_MESSAGE));

    let second = RecordedLogCallback::default();
    assert!(set_log_callback(LogLevel::Debug, Box::new(second.clone())).is_err());

    log::info!("{SECOND_MESSAGE}");
    assert!(!second.received(SECOND_MESSAGE));
    assert!(first.received(SECOND_MESSAGE));
}
