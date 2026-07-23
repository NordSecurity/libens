#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#![allow(clippy::missing_errors_doc)]

mod client;
mod logging;
mod memory;
mod panics;
mod runtime;

use llt_proto::ens::ConnectionError;
use log::{debug, warn};
use parking_lot::Mutex;
use std::{net::SocketAddr, panic::AssertUnwindSafe, sync::Arc, time::Duration};
use telio_sockets::{protector::make_external_protector, NativeProtector, SocketPool};
use telio_utils::exponential_backoff::{ExponentialBackoff, ExponentialBackoffBounds};
use thiserror::Error;

pub use memory::get_memory_usage;

use crate::{
    client::ErrorNotificationService,
    logging::LogCallbackHolder,
    panics::{catch_panic, catch_panic_result},
    runtime::{deinit_runtime, get_runtime, init_runtime},
};

mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

static APP_VERSION: Mutex<Option<String>> = Mutex::new(None);

type Result<T> = std::result::Result<T, EnsError>;

#[derive(Debug, Error)]
pub enum EnsError {
    #[error("Transport error: {reason}")]
    TransportError { reason: String },
    #[error("Grpc status error: {reason}")]
    StatusError { reason: String },
    #[error("Internal error: {reason}")]
    InternalError { reason: String },
    #[error("Library not yet initialized: {reason}")]
    NotInitialized { reason: String },
    #[error("Library already initialized")]
    AlreadyInitialized,
    #[error("Unknown error: {reason}")]
    UnknownError { reason: String },
}

impl From<client::Error> for EnsError {
    fn from(value: client::Error) -> Self {
        match value {
            client::Error::MalformedVpnUri(error) => Self::InternalError {
                reason: format!("Malformed vpn uri: {error}"),
            },
            client::Error::Transport(error) => Self::TransportError {
                reason: error.to_string(),
            },
            client::Error::Status(status) => Self::StatusError {
                reason: status.to_string(),
            },
            client::Error::ExponentialBackoff(error) => Self::InternalError {
                reason: format!("Exponential backoff failure: {error}"),
            },
            client::Error::UuidParsing(error) => Self::InternalError {
                reason: format!("UUID error: {error}"),
            },
            client::Error::InvalidMetadata(invalid_metadata_value) => Self::InternalError {
                reason: format!("Invalid grpc metadata value: {invalid_metadata_value}"),
            },
            client::Error::InvalidKey { reason } => Self::UnknownError { reason },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

pub trait LogCallback: Send + Sync {
    fn log(&self, log_level: LogLevel, message: String);
}

pub fn set_log_callback(max_level: LogLevel, callback: Box<dyn LogCallback>) -> Result<()> {
    catch_panic_result(|| {
        let callback = LogCallbackHolder::new(callback);
        logging::set_log_callback(max_level, callback)
    })
}

#[must_use]
pub fn get_version() -> String {
    catch_panic(
        || format!("v{}", built_info::PKG_VERSION),
        "unknown".to_owned(),
    )
}

/// Initialize the library. Needs to be called before any other function is called.
pub fn init(app_version: String) -> Result<()> {
    catch_panic_result(|| {
        let mut ver = APP_VERSION.lock();
        let was_initialized = ver.is_some();

        if was_initialized {
            return Err(EnsError::AlreadyInitialized);
        }

        init_runtime()?;

        *ver = Some(app_version);
        if let Some(app_version) = ver.as_ref() {
            print_version_info(app_version);
        }

        Ok(())
    })
}

fn print_version_info(app_version: &str) {
    use built_info::{BUILT_TIME_UTC, GIT_DIRTY, GIT_VERSION, RUSTC_VERSION};
    let version = get_version();
    let git_version = GIT_VERSION.unwrap_or("unknown-git-version");
    let dirty = match GIT_DIRTY {
        Some(true) => "-dirty",
        _ => "",
    };
    // This results in a log like this:
    // libens initialized, app version ens-cli v0.1.0, libens version v0.0.1 (ea521fb-dirty) built on Wed, 29 Jul 2026 07:52:04 +0000 using compiler rustc 1.97.1 (8bab26f4f 2026-07-14)
    log::info!("libens initialized, app version {app_version}, libens version {version} ({git_version}{dirty}) built on {BUILT_TIME_UTC} using compiler {RUSTC_VERSION}");
}

/// Deinitializes the library. After calling this, calls to other functions
/// will fail.
pub fn deinit() -> Result<()> {
    catch_panic_result(|| {
        let mut ver = APP_VERSION.lock();

        let was_initialized = ver.is_some();
        if !was_initialized {
            return Err(EnsError::NotInitialized {
                reason: "deinit".to_owned(),
            });
        }

        deinit_runtime();
        *ver = None;

        Ok(())
    })
}

pub enum ConnectionErrorNotificationKind {
    Unknown { kind: i32 },
    ConnectionLimitReached,
    ServerMaintenance, // Only this error type can cause automatic recconection to a different server
    Unauthenticated,
    Superseded,
}

pub struct ConnectionErrorNotification {
    pub kind: ConnectionErrorNotificationKind,
    pub additional_info: Option<String>,
}

impl From<ConnectionError> for ConnectionErrorNotification {
    fn from(value: ConnectionError) -> Self {
        use llt_proto::ens::Error as GrpcError;

        let kind = match value.code {
            code if code == GrpcError::ConnectionLimitReached as i32 => {
                ConnectionErrorNotificationKind::ConnectionLimitReached
            }
            code if code == GrpcError::ServerMaintenance as i32 => {
                ConnectionErrorNotificationKind::ServerMaintenance
            }
            code if code == GrpcError::Unauthenticated as i32 => {
                ConnectionErrorNotificationKind::Unauthenticated
            }
            code if code == GrpcError::Superseded as i32 => {
                ConnectionErrorNotificationKind::Superseded
            }
            other => ConnectionErrorNotificationKind::Unknown { kind: other },
        };

        ConnectionErrorNotification {
            kind,
            additional_info: value.additional_info,
        }
    }
}

pub trait ErrorNotificationCallback: Send + Sync {
    fn notify(&self, notification: ConnectionErrorNotification);
    fn disconnected(&self, reason: Option<String>);
}

pub enum CredentialsKind {
    OpenVPN,
    NordWhisper,
}

pub struct Credentials {
    pub username: String,
    pub password: String,
    pub kind: CredentialsKind,
}

pub enum KeyKind {
    NordLynx,
}

pub struct Keys {
    pub local_private_key: Vec<u8>,
    pub vpn_public_key: Vec<u8>,
    pub kind: KeyKind,
}

pub enum Authentication {
    Credentials { credentials: Credentials },
    Keys { keys: Keys },
}

pub trait ProtectCallback: Send + Sync {
    fn protect(&self, _socket_id: i32) -> Result<()>;
}

#[derive(Clone)]
struct ConfigState {
    buffer_size: usize,
    allow_only_pq: bool,
    root_certificate_override: Option<Vec<u8>>,
    backoff: ExponentialBackoffBounds,
}

pub struct Config {
    state: Mutex<ConfigState>,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    #[must_use]
    pub fn new() -> Self {
        let state = ConfigState {
            buffer_size: 5,
            allow_only_pq: true,
            root_certificate_override: None,
            backoff: ExponentialBackoffBounds {
                initial: Duration::from_secs(2),
                maximal: Some(Duration::from_secs(120)),
            },
        };

        Self {
            state: Mutex::new(state),
        }
    }

    pub fn set_buffer_size(&self, buffer_size: u32) {
        self.state.lock().buffer_size = buffer_size as usize;
    }

    pub fn set_allow_only_pq(&self, allow_only_pq: bool) {
        self.state.lock().allow_only_pq = allow_only_pq;
    }

    pub fn set_root_certificate_override(&self, root_certificate_override: Option<Vec<u8>>) {
        self.state.lock().root_certificate_override = root_certificate_override;
    }

    pub fn set_backoff_initial(&self, seconds: u32) {
        self.state.lock().backoff.initial = Duration::from_secs(seconds.into());
    }

    pub fn set_backoff_maximal(&self, seconds: Option<u32>) {
        self.state.lock().backoff.maximal = seconds.map(|s| Duration::from_secs(s.into()));
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn connect(
    vpn: SocketAddr,
    protect_cb: Option<Box<dyn ProtectCallback>>,
    authentication: Authentication,
    callback: Box<dyn ErrorNotificationCallback>,
    config: Arc<Config>,
) -> Result<Arc<Connection>> {
    catch_panic_result(|| {
        let config = config.state.lock().clone();

        connect_impl(vpn, protect_cb, authentication, callback, config)
    })
}

fn connect_impl(
    vpn: SocketAddr,
    protect_cb: Option<Box<dyn ProtectCallback>>,
    authentication: Authentication,
    callback: Box<dyn ErrorNotificationCallback>,
    config: ConfigState,
) -> Result<Arc<Connection>> {
    let protect: Option<telio_sockets::Protect> = match protect_cb {
        Some(protect) => {
            let protect = AssertUnwindSafe(protect);
            #[allow(clippy::useless_conversion)]
            Some(Arc::new(move |fd| match fd.try_into() {
                Ok(fd) => {
                    let protect_res = protect.protect(fd);
                    if let Err(err) = protect_res {
                        warn!("Could not call protect callback due to {err:?}");
                    }
                }
                Err(e) => {
                    warn!("Failed to convert file descriptor: {e}");
                }
            }))
        }
        _ => None,
    };

    let socket_pool = Arc::new({
        if let Some(protect) = protect {
            let external_protect = make_external_protector(protect);
            SocketPool::new(external_protect)
        } else {
            #[cfg(target_os = "macos")]
            let np = NativeProtector::new(false);
            #[cfg(not(target_os = "macos"))]
            let np = NativeProtector::new();

            SocketPool::new(np.map_err(|e| EnsError::InternalError {
                reason: format!("Native protector creation failed: {e}"),
            })?)
        }
    });

    let (mut client, mut receiver) = ErrorNotificationService::new(
        config.buffer_size,
        socket_pool,
        config.allow_only_pq,
        config.root_certificate_override,
    );

    let backoff: ExponentialBackoff = ExponentialBackoff::new(config.backoff).unwrap_or_else(|e| {
        let ret = ExponentialBackoff::fallback();
        warn!("Failed to construct backoff: {e}, falling back to: {ret:?}");
        ret
    });

    client.start_monitor_on_port(vpn.ip(), vpn.port(), authentication, backoff);

    tokio::task::spawn(async move {
        while let Some((connection_error, vpn)) = receiver.recv().await {
            debug!("Received new connection error: {connection_error:?} from {vpn:?}");

            callback.notify(connection_error.into());
        }

        debug!("Stopping ENS worker thread for {vpn:?}");
    });

    Ok(Arc::new(Connection {
        client: tokio::sync::Mutex::new(client),
    }))
}

pub struct Connection {
    client: tokio::sync::Mutex<ErrorNotificationService>,
}

impl Connection {
    pub fn shutdown(&self) -> Result<()> {
        let handle = get_runtime()?;

        handle.block_on(async {
            let mut client = self.client.lock().await;
            client.stop();
        });

        Ok(())
    }
}
