use chrono::Utc;
use ens::{LogCallback, LogLevel};
use log::info;

struct StdoutLogCallback;

impl LogCallback for StdoutLogCallback {
    fn log(&self, log_level: LogLevel, message: String) {
        let date = Utc::now();
        let level = format!("{log_level:?}").to_ascii_uppercase();
        eprintln!("{date:?} {level} {message}");
    }
}

fn main() {
    let log_callback = Box::new(StdoutLogCallback);
    ens::set_log_callback(LogLevel::Info, log_callback).unwrap();
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    ens::init(format!("{name} v{version}")).unwrap();
    info!("version: {}", ens::get_version());
    info!("memory usage: {}", ens::get_memory_usage());
    ens::deinit().unwrap();
}
