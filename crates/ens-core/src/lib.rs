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
pub mod runtime;

use llt_proto::ens::ConnectionError;
use log::{debug, warn};
use parking_lot::Mutex;
use std::{
    fmt::Display, net::SocketAddr, panic::AssertUnwindSafe, str::FromStr, sync::Arc, time::Duration,
};
use telio_sockets::{protector::make_external_protector, NativeProtector, SocketPool};
use telio_utils::exponential_backoff::{ExponentialBackoff, ExponentialBackoffBounds};
use thiserror::Error;
use tokio::task::block_in_place;

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

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
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

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{self:?}").to_ascii_lowercase();
        f.write_str(&s)
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        match s.as_str() {
            "error" => Ok(Self::Error),
            "warning" => Ok(Self::Warning),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            other => Err(other.to_owned()),
        }
    }
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

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionErrorNotificationKind {
    Unknown { kind: i32 },
    ConnectionLimitReached,
    ServerMaintenance, // Only this error type can cause automatic recconection to a different server
    Unauthenticated,
    Superseded,
}

#[derive(Debug, PartialEq, Eq)]
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

        let handle = get_runtime()?;

        block_in_place(|| {
            handle.block_on(connect_impl(
                vpn,
                protect_cb,
                authentication,
                callback,
                config,
            ))
        })
    })
}

async fn connect_impl(
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

    client
        .start_monitor_on_port(vpn.ip(), vpn.port(), authentication, backoff)
        .await;

    let state = Arc::new(Mutex::new(ConnectionState::Active(client)));

    let state_clone = state.clone();

    let callback_thread_id = Arc::new(Mutex::new(None));
    let callback_thread_id_clone = callback_thread_id.clone();

    let event_processing_task = tokio::task::spawn(async move {
        while let Some((connection_error, vpn)) = receiver.recv().await {
            // This is behaviour documented in the udl
            if state_clone.lock().is_shut_down() {
                debug!("Dropping notification received after shutdown: {connection_error:?}");
                break;
            }

            debug!("Received new connection error: {connection_error:?} from {vpn:?}");
            {
                let _guard = CallbackThreadGuard::enter(&callback_thread_id_clone);
                callback.notify(connection_error.into());
            }
        }

        let reason = match &*state_clone.lock() {
            ConnectionState::ShutDown(reason) => reason.clone(),
            ConnectionState::Active(_) => {
                Some("active service closed the notification stream".to_owned())
            }
        };
        {
            let _guard = CallbackThreadGuard::enter(&callback_thread_id_clone);
            callback.disconnected(reason);
        }

        debug!("Stopping ENS notification pump");
    });

    Ok(Arc::new(Connection {
        state,
        callback_thread_id,
        event_processing_task: Mutex::new(Some(event_processing_task)),
    }))
}

enum ConnectionState {
    Active(ErrorNotificationService),
    ShutDown(Option<String>),
}

impl ConnectionState {
    fn is_shut_down(&self) -> bool {
        matches!(self, ConnectionState::ShutDown(_))
    }
}

type CallbackThreadId = Mutex<Option<std::thread::ThreadId>>;
struct CallbackThreadGuard<'a>(&'a CallbackThreadId);

impl<'a> CallbackThreadGuard<'a> {
    fn enter(thread_id: &'a CallbackThreadId) -> Self {
        *thread_id.lock() = Some(std::thread::current().id());
        Self(thread_id)
    }
}

impl Drop for CallbackThreadGuard<'_> {
    fn drop(&mut self) {
        *self.0.lock() = None;
    }
}

pub struct Connection {
    state: Arc<Mutex<ConnectionState>>,
    // Set to Some(_) when the event processing task is about to call one of
    // the user provided callbacks. Which means that it's None when called from
    // other threads.
    callback_thread_id: Arc<CallbackThreadId>,

    event_processing_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Connection {
    pub fn shutdown(&self) -> Result<()> {
        catch_panic_result(|| {
            let mut service = {
                let mut state = self.state.lock();
                match std::mem::replace(
                    &mut *state,
                    ConnectionState::ShutDown(Some("shutdown".to_owned())),
                ) {
                    ConnectionState::Active(s) => s,
                    already_shut @ ConnectionState::ShutDown(_) => {
                        *state = already_shut;
                        return Ok(());
                    }
                }
            };

            let event_processing_task = self.event_processing_task.lock().take();
            let called_from_own_callback =
                *self.callback_thread_id.lock() == Some(std::thread::current().id());
            let event_processing_task = if called_from_own_callback {
                debug!("`shutdown` called from `notify` a callback, not awaiting the end of event processing task");
                None
            } else {
                event_processing_task
            };

            let handle = get_runtime()?;
            let stop_service = async move {
                service.stop().await;
                // We need to drop it to trigger closing of the channel, otherwise
                // the await below would deadlock.
                drop(service);

                if let Some(task) = event_processing_task {
                    if let Err(e) = task.await {
                        if !e.is_cancelled() {
                            warn!("ENS notification pump failed to stop: {e}");
                        }
                    }
                }
            };
            block_in_place(|| {
                handle.block_on(async move {
                    tokio::time::timeout(SHUTDOWN_TIMEOUT, stop_service).await
                })
            })
            .map_err(|e| EnsError::InternalError {
                reason: format!("Failed while waiting for the ENS task to stop: {e}"),
            })
        })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if matches!(&*state, ConnectionState::Active(_)) {
            *state = ConnectionState::ShutDown(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::tests::{run_init, Command, ServerConfig};
    use assert_matches::assert_matches;
    use llt_proto::ens::Error as EnsProtoError;
    use log::info;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use telio_crypto::SecretKey;

    use super::*;

    #[derive(Default)]
    struct RecordedCallback {
        notifications: Mutex<Vec<ConnectionErrorNotification>>,

        // Outer Option: whether `disconnected` was called at all.
        // Inner Option<String>: the reason passed in.
        disconnected: Mutex<Option<Option<String>>>,

        /// Simulate `disconnected` being slow
        disconnect_delay: Mutex<Duration>,
    }

    impl ErrorNotificationCallback for Arc<RecordedCallback> {
        fn notify(&self, notification: ConnectionErrorNotification) {
            self.notifications.lock().push(notification);
        }

        fn disconnected(&self, reason: Option<String>) {
            let delay = *self.disconnect_delay.lock();
            std::thread::sleep(delay);
            *self.disconnected.lock() = Some(reason);
        }
    }

    #[derive(Default)]
    struct RecursiveCallback {
        connection: Mutex<Option<Arc<Connection>>>,
        notifications: Mutex<Vec<ConnectionErrorNotification>>,

        shutdown_results: Mutex<Vec<Result<()>>>,
        disconnected: Mutex<Option<Option<String>>>,
    }

    impl ErrorNotificationCallback for Arc<RecursiveCallback> {
        fn notify(&self, notification: ConnectionErrorNotification) {
            info!("Got {notification:?}");
            self.notifications.lock().push(notification);

            // Clone the handle out and release the lock before shutting down:
            // `shutdown` blocks, and holding a lock across it would make the
            // callback itself a source of deadlocks.
            let connection = self.connection.lock().clone();

            if let Some(c) = connection {
                info!("connection present, shutting down");
                self.shutdown_results.lock().push(c.shutdown());
            }
        }

        fn disconnected(&self, reason: Option<String>) {
            info!("disconnect: {reason:?}");
            *self.disconnected.lock() = Some(reason);
        }
    }

    #[track_caller]
    fn wait_for(mut predicate: impl FnMut() -> bool) {
        let max_wait_time = Duration::from_secs(5);
        let deadline = std::time::Instant::now() + max_wait_time;
        loop {
            if predicate() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("Timed out in wait_for");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn connect_to_test_server(
        server_config: &ServerConfig,
        callback: impl ErrorNotificationCallback + 'static,
    ) -> Arc<Connection> {
        let client_private_key = SecretKey::gen();

        let config = Config::new();
        config.set_root_certificate_override(Some(server_config.tls_config.ca_cert.der().to_vec()));

        connect(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, server_config.port)),
            None,
            Authentication::Keys {
                keys: Keys {
                    local_private_key: client_private_key.to_vec(),
                    vpn_public_key: server_config.public_key.to_vec(),
                    kind: crate::KeyKind::NordLynx,
                },
            },
            Box::new(callback),
            Arc::new(config),
        )
        .unwrap()
    }

    #[test_log::test]
    fn test_explicit_shutdown() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(crate::client::tests::spawn_server());
        let callback = Arc::new(RecordedCallback::default());
        let connection = connect_to_test_server(&server_config, callback.clone());

        let errors_to_emit = [
            ConnectionError {
                code: EnsProtoError::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: EnsProtoError::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
            ConnectionError {
                code: EnsProtoError::ServerMaintenance as i32,
                additional_info: Some("planned maintenance".to_owned()),
            },
        ];

        runtime.block_on(async {
            for e in &errors_to_emit {
                server_config
                    .command_tx
                    .send(Command::Send(e.clone()))
                    .await
                    .unwrap();
            }
        });

        wait_for(|| callback.notifications.lock().len() == errors_to_emit.len());

        *callback.disconnect_delay.lock() = Duration::from_millis(500);
        connection.shutdown().unwrap();

        // No need for `wait_for` because `shutdown` should have already waited
        // until the end of the event processing task which calls `disconnected`
        // on the callback.
        assert!(
            callback.disconnected.lock().is_some(),
            "shutdown() returned before the pump delivered `disconnected`"
        );

        let notifications = callback.notifications.lock();
        assert_eq!(
            *notifications,
            vec![
                ConnectionErrorNotification {
                    kind: ConnectionErrorNotificationKind::Unknown { kind: 0 },
                    additional_info: None,
                },
                ConnectionErrorNotification {
                    kind: ConnectionErrorNotificationKind::ConnectionLimitReached,
                    additional_info: Some("additional info".to_owned()),
                },
                ConnectionErrorNotification {
                    kind: ConnectionErrorNotificationKind::ServerMaintenance,
                    additional_info: Some("planned maintenance".to_owned()),
                }
            ]
        );

        assert_eq!(
            *callback.disconnected.lock(),
            Some(Some("shutdown".to_owned()))
        );

        // `shutdown` should be idempotent
        assert_matches!(connection.shutdown(), Ok(()));
    }

    #[test_log::test]
    fn test_implicit_shutdown() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(crate::client::tests::spawn_server());
        let callback = Arc::new(RecordedCallback::default());
        let connection = connect_to_test_server(&server_config, callback.clone());

        let error = ConnectionError {
            code: EnsProtoError::Unauthenticated as i32,
            additional_info: None,
        };

        runtime.block_on(async {
            server_config
                .command_tx
                .send(Command::Send(error.clone()))
                .await
                .unwrap();
        });

        wait_for(|| callback.notifications.lock().len() == 1);

        drop(connection);

        // `drop` doesn't wait so we need to
        wait_for(|| callback.disconnected.lock().is_some());

        let notifications = callback.notifications.lock();
        assert_eq!(
            *notifications,
            vec![ConnectionErrorNotification {
                kind: ConnectionErrorNotificationKind::Unauthenticated,
                additional_info: None,
            }]
        );

        assert_eq!(*callback.disconnected.lock(), Some(None));
    }

    #[test_log::test]
    fn test_shutdown_called_by_callback() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(crate::client::tests::spawn_server());
        let callback = Arc::new(RecursiveCallback::default());
        let connection = connect_to_test_server(&server_config, callback.clone());
        *callback.connection.lock() = Some(connection.clone());

        let errors_to_emit = [
            ConnectionError {
                code: EnsProtoError::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: EnsProtoError::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
            ConnectionError {
                code: EnsProtoError::ServerMaintenance as i32,
                additional_info: Some("planned maintenance".to_owned()),
            },
        ];

        runtime.block_on(async {
            for e in &errors_to_emit {
                server_config
                    .command_tx
                    .send(Command::Send(e.clone()))
                    .await
                    .unwrap();
            }
        });

        wait_for(|| callback.disconnected.lock().is_some());

        // callback will call `shutdown` when receiving first notification, so
        // the other two should not be delivered.
        let notifications = std::mem::take(&mut *callback.notifications.lock());
        assert_eq!(
            notifications,
            vec![ConnectionErrorNotification {
                kind: ConnectionErrorNotificationKind::Unknown { kind: 0 },
                additional_info: None,
            }],
            "no notification may be delivered once shutdown() was called"
        );

        assert_matches!(
            std::mem::take(&mut *callback.shutdown_results.lock()).as_slice(),
            [Ok(())]
        );

        assert_eq!(
            *callback.disconnected.lock(),
            Some(Some("shutdown".to_owned()))
        );
    }
}
