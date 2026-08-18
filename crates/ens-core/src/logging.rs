use std::sync::LazyLock;

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use telio_utils::log_censor::{LogCensor, LogCensorMode};

use crate::{EnsError, LogCallback, LogLevel};

pub static LOG_CENSOR: LazyLock<LogCensor> = LazyLock::new(|| {
    let mut log_censor = LogCensor::default();
    if cfg!(debug_assertions) {
        log_censor.set_enabled(false);
    } else {
        log_censor.set_enabled(true);
        log_censor.set_mode(LogCensorMode::Dots);
    }
    log_censor
});

pub struct LogCallbackHolder {
    callback: Box<dyn LogCallback>,
}

impl LogCallbackHolder {
    pub fn new(callback: Box<dyn LogCallback>) -> Self {
        Self { callback }
    }

    pub fn log(&self, level: LogLevel, message: impl Into<String>) {
        self.callback.log(level, message.into());
    }
}

struct CallbackLogger {
    level: LevelFilter,
    callback: LogCallbackHolder,
}

impl Log for CallbackLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let path = record.module_path().unwrap_or("unknown");
        let msg = format!(
            "{path} {}",
            LOG_CENSOR.censor_logs(record.args().to_string())
        );

        self.callback.log(record.level().into(), msg);
    }

    fn flush(&self) {
        // This is empty by design, the callback based logging has no concept of
        // flushing.
    }
}

pub fn set_log_callback(max_level: LogLevel, callback: LogCallbackHolder) -> Result<(), EnsError> {
    let level = max_level.into();
    let logger = CallbackLogger { level, callback };
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(level))
        .map_err(|e| map_set_logger_error(&e))
}

fn map_set_logger_error(error: &SetLoggerError) -> EnsError {
    EnsError::InternalError {
        reason: format!("failed to set logger: {error}"),
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warning => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl From<Level> for LogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => LogLevel::Error,
            Level::Warn => LogLevel::Warning,
            Level::Info => LogLevel::Info,
            Level::Debug => LogLevel::Debug,
            Level::Trace => LogLevel::Trace,
        }
    }
}
