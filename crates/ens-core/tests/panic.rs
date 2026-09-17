#[path = "../src/test_support.rs"]
mod test_support;

use ens_core::{panics::catch_panic, set_log_callback, LogLevel};

use test_support::RecordedLogCallback;

#[test]
fn test_catch_panic() {
    let callback = RecordedLogCallback::default();
    set_log_callback(LogLevel::Debug, Box::new(callback.clone())).unwrap();
    let v = catch_panic(|| -> u32 { panic!("foo") }, 42);
    assert_eq!(42, v);
    let entries = callback.entries();
    assert_eq!(1, entries.len());
    assert_eq!(LogLevel::Error, entries[0].0);
    assert!(entries[0].1.contains("foo"));
}
