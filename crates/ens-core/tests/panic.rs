use ens_core::{panics::catch_panic, set_log_callback, LogCallback, LogLevel};
use std::sync::{Arc, Mutex};

type LogEntry = (LogLevel, String);

struct RecordingCallback {
    storage: Arc<Mutex<Vec<LogEntry>>>,
}

impl RecordingCallback {
    pub fn new(storage: Arc<Mutex<Vec<LogEntry>>>) -> Self {
        Self { storage }
    }
}

impl LogCallback for RecordingCallback {
    fn log(&self, log_level: LogLevel, message: String) {
        self.storage.lock().unwrap().push((log_level, message));
    }
}

#[test]
fn test_catch_panic() {
    let storage = Arc::new(Mutex::new(vec![]));
    let callback = Box::new(RecordingCallback::new(storage.clone()));
    set_log_callback(LogLevel::Debug, callback).unwrap();
    let v = catch_panic(|| -> u32 { panic!("foo") }, 42);
    assert_eq!(42, v);
    let storage = storage.lock().unwrap().clone();
    assert_eq!(1, storage.len());
    assert_eq!(LogLevel::Error, storage[0].0);
    assert!(storage[0].1.contains("foo"));
}
