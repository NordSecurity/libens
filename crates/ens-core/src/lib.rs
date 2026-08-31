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
pub mod panics;
pub mod runtime;

#[cfg(test)]
extern crate self as ens_core;
#[cfg(test)]
mod test_support;

use http::{header::InvalidHeaderValue, HeaderValue};
use llt_proto::ens::ConnectionError;
use log::{debug, info, warn};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    fmt::Display,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc, Weak},
    time::Duration,
};
use telio_sockets::{protector::make_external_protector, NativeProtector, SocketPool};
use telio_utils::exponential_backoff::{ExponentialBackoff, ExponentialBackoffBounds};
use thiserror::Error;
use tokio::task::block_in_place;
use tonic::metadata::AsciiMetadataValue;
use uuid::Uuid;

pub use memory::get_memory_usage;

pub use telio_utils::{Hidden, HiddenBytes, HiddenString};

use crate::{
    client::{
        ErrorNotificationService, KeepaliveConfig, DEFAULT_KEEPALIVE_INTERVAL,
        DEFAULT_KEEPALIVE_TIMEOUT,
    },
    logging::LogCallbackHolder,
    panics::{catch_panic, catch_panic_result},
    runtime::{deinit_runtime, get_runtime, init_runtime, is_unexpected_task_failure},
};

mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

// Reason reported to `ErrorNotificationCallback::disconnected` when the
// session was ended by `Connection::shutdown`.
pub const SHUTDOWN_REASON: &str = "shutdown";

static STATE: Mutex<Option<GlobalState>> = Mutex::new(None);

struct GlobalState {
    user_agent: HeaderValue,
    active_connections: HashMap<Uuid, Weak<Connection>>,
}

struct ActiveConnectionGuard(Uuid);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        if let Some(state) = &mut *STATE.lock() {
            state.active_connections.remove(&self.0);
        }
    }
}

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
            client::Error::Internal { reason } => Self::InternalError { reason },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[allow(clippy::needless_pass_by_value)]
pub fn init(app_version: String) -> Result<()> {
    catch_panic_result(|| {
        let mut state = STATE.lock();
        let was_initialized = state.is_some();

        if was_initialized {
            return Err(EnsError::AlreadyInitialized);
        }

        let user_agent = build_user_agent(&app_version).map_err(|e| EnsError::UnknownError {
            reason: format!("incorrect user-agent: {e}"),
        })?;

        init_runtime()?;

        *state = Some(GlobalState {
            user_agent,
            active_connections: HashMap::default(),
        });

        if let Some(state) = state.as_ref() {
            info!(
                "libens initialized ({:?}) built on {} using {}",
                state.user_agent,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION
            );
        }

        Ok(())
    })
}

fn build_user_agent(app_version: &str) -> std::result::Result<HeaderValue, InvalidHeaderValue> {
    // As specified in:
    // https://www.rfc-editor.org/rfc/rfc9110.html#comments
    use built_info::{GIT_DIRTY, GIT_VERSION};
    let version = get_version();
    let git_version = GIT_VERSION.unwrap_or("unknown-git-version");
    let dirty = match GIT_DIRTY {
        Some(true) => "-dirty",
        _ => "",
    };

    // Example return value:
    // ens-cli/v0.1.0 libens/v0.0.1 macos (4bb26d4-dirty)
    format!(
        "{app_version} libens/{version} {} ({git_version}{dirty})",
        built_info::CFG_OS
    )
    .try_into()
}

/// Deinitializes the library. After calling this, calls to other functions
/// will fail. Calling `init` or `connect` while `deinit` is running is an error
/// and can lead to incorrect behaviour.
pub fn deinit() -> Result<()> {
    catch_panic_result(|| {
        // The connections are shut down without holding the `STATE` lock,
        // because their event processing tasks need it to deregister
        // themselves while we are waiting for them to stop.
        let active_connections = {
            let mut state = STATE.lock();
            let Some(global_state) = &mut *state else {
                return Err(EnsError::NotInitialized {
                    reason: "deinit".to_owned(),
                });
            };
            let active_connections = std::mem::take(&mut global_state.active_connections);

            *state = None;
            active_connections
        };

        for connection in active_connections.values() {
            let Some(connection) = connection.upgrade() else {
                continue;
            };
            if let Err(e) = connection.shutdown() {
                warn!(
                    "Failed to shutdown ENS connection to {}: {e:?}",
                    connection.vpn
                );
            }
        }

        deinit_runtime();

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
    pub username: HiddenString,
    pub password: HiddenString,
    pub kind: CredentialsKind,
}

pub enum KeyKind {
    NordLynx,
}

impl KeyKind {
    #[must_use]
    pub fn protocol_name(&self) -> AsciiMetadataValue {
        match self {
            KeyKind::NordLynx => AsciiMetadataValue::from_static("nordlynx"),
        }
    }
}

pub struct Keys {
    pub local_private_key: HiddenBytes,
    pub vpn_public_key: HiddenBytes,
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
    keepalive: KeepaliveConfig,
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
            keepalive: KeepaliveConfig {
                interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
                timeout: Some(DEFAULT_KEEPALIVE_TIMEOUT),
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

    pub fn set_keepalive_interval(&self, seconds: Option<u32>) {
        self.state.lock().keepalive.interval = seconds.map(|s| Duration::from_secs(s.into()));
    }

    pub fn set_keepalive_timeout(&self, seconds: Option<u32>) {
        self.state.lock().keepalive.timeout = seconds.map(|s| Duration::from_secs(s.into()));
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

        let connection = block_in_place(|| {
            handle.block_on(connect_impl(
                vpn,
                protect_cb,
                authentication,
                callback,
                config,
            ))
        });

        if let Ok(connection) = connection.as_ref() {
            if let Some(state) = STATE.lock().as_mut() {
                let id = connection.id;
                state
                    .active_connections
                    .insert(id, Arc::downgrade(connection));
            }
        }

        connection
    })
}

async fn connect_impl(
    vpn: SocketAddr,
    protect_cb: Option<Box<dyn ProtectCallback>>,
    authentication: Authentication,
    callback: Box<dyn ErrorNotificationCallback>,
    config: ConfigState,
) -> Result<Arc<Connection>> {
    let connection_id = Uuid::new_v4();
    let authentication = authentication.try_into()?;
    let callback = GuardedCallback::new(callback);
    let protect = make_socket_protector(protect_cb);
    let socket_pool = make_socket_pool(protect)?;

    let user_agent = STATE
        .lock()
        .as_ref()
        .ok_or_else(|| EnsError::NotInitialized {
            reason: "global state not initialized".to_owned(),
        })?
        .user_agent
        .clone();

    let (mut client, mut receiver) = ErrorNotificationService::new(
        config
            .buffer_size
            .try_into()
            .map_err(|e| EnsError::UnknownError {
                reason: format!("buffer_size has to be non zero: {e}"),
            })?,
        socket_pool,
        config.allow_only_pq,
        config.root_certificate_override,
        config.keepalive,
        user_agent,
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
        let _active_connection = ActiveConnectionGuard(connection_id);
        loop {
            match receiver.recv().await {
                Some(client::Event::Notification {
                    connection_error,
                    vpn_uri,
                }) => {
                    // This is behaviour documented in the udl
                    if state_clone.lock().is_finished() {
                        debug!(
                            "Dropping notification received after shutdown: {connection_error:?}"
                        );
                        break;
                    }

                    debug!("Received new connection error: {connection_error:?} from {vpn_uri:?}");
                    {
                        let _guard = CallbackThreadGuard::enter(&callback_thread_id_clone);
                        callback.notify(connection_error.into());
                    }
                }
                Some(client::Event::Disconnect(reason)) => {
                    warn!("Got a disconnect with a reason: {reason:?}");
                    let mut state = state_clone.lock();
                    if !state.is_finished() {
                        *state = ConnectionState::Ended(reason);
                    }
                    break;
                }
                None => break,
            }
        }

        let reason = match &*state_clone.lock() {
            ConnectionState::Ended(reason) | ConnectionState::ShutDown(reason) => reason.clone(),
            ConnectionState::Active(_) => {
                Some("active service closed the notification stream".to_owned())
            }
        };
        {
            debug!("disconnect after loop end: {reason:?}");
            let _guard = CallbackThreadGuard::enter(&callback_thread_id_clone);
            callback.disconnected(reason);
        }

        debug!("Stopping ENS notification pump");
    });

    Ok(Arc::new(Connection {
        id: connection_id,
        state,
        callback_thread_id,
        event_processing_task: Mutex::new(Some(event_processing_task)),
        vpn,
    }))
}

fn make_socket_protector(
    protect_cb: Option<Box<dyn ProtectCallback>>,
) -> Option<telio_sockets::Protect> {
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

    protect
}

fn make_socket_pool(protect: Option<telio_sockets::Protect>) -> Result<Arc<SocketPool>> {
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

    Ok(socket_pool)
}

struct GuardedCallback {
    closed: AtomicBool,
    inner: Box<dyn ErrorNotificationCallback>,
}

impl GuardedCallback {
    pub fn new(inner: Box<dyn ErrorNotificationCallback>) -> Self {
        Self {
            inner,
            closed: AtomicBool::new(false),
        }
    }
}

impl ErrorNotificationCallback for GuardedCallback {
    fn notify(&self, notification: ConnectionErrorNotification) {
        if !self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            self.inner.notify(notification);
        }
    }

    fn disconnected(&self, reason: Option<String>) {
        let was_closed = self.closed.swap(true, std::sync::atomic::Ordering::Relaxed);
        if !was_closed {
            self.inner.disconnected(reason);
        }
    }
}

#[derive(Debug)]
enum ConnectionState {
    Active(ErrorNotificationService),
    // The session ended on its own with stored reason
    Ended(Option<String>),
    // The session was torn down by the library caller.
    ShutDown(Option<String>),
}

impl ConnectionState {
    fn is_finished(&self) -> bool {
        !matches!(self, ConnectionState::Active(_))
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

#[derive(Debug)]
pub struct Connection {
    id: Uuid,
    vpn: SocketAddr,
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
                    ConnectionState::ShutDown(Some(SHUTDOWN_REASON.to_owned())),
                ) {
                    ConnectionState::Active(s) => s,
                    already_finished => {
                        *state = already_finished;
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
                        if is_unexpected_task_failure(&e) {
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

    use crate::{
        client::tests::{global_user_agent, spawn_authenticating_server},
        test_support::{
            connect_to_test_server, connect_to_test_server_with_keys, wait_for,
            wait_for_disconnect_reason, Command, RecordedCallback, SHUTDOWN_REASON,
        },
    };

    use assert_matches::assert_matches;
    use llt_proto::ens::Error as EnsProtoError;
    use log::info;
    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();
    pub fn run_init() {
        INIT.call_once(|| init("unit-tests".to_owned()).unwrap());
    }

    #[derive(Default)]
    struct RecursiveCallback {
        connection: Mutex<Option<Arc<Connection>>>,
        notifications: Mutex<Vec<ConnectionErrorNotification>>,

        shutdown_results: Mutex<Vec<Result<()>>>,
        #[allow(clippy::option_option)]
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

    const MALFORMED_PRIVATE_KEY: &[u8] = &[0x01, 0x02, 0x03];

    const RECONNECT_COUNT: usize = 5;

    fn tracked_connections(ids: &[Uuid]) -> usize {
        let state = STATE.lock();
        let Some(state) = state.as_ref() else {
            return 0;
        };
        ids.iter()
            .filter(|id| state.active_connections.contains_key(*id))
            .count()
    }

    #[test_log::test]
    fn test_guarded_callback_reports_a_disconnect_at_most_once() {
        let recording = RecordedCallback::default();
        let callback = GuardedCallback::new(Box::new(recording.clone()));

        callback.disconnected(Some(SHUTDOWN_REASON.to_owned()));
        callback.disconnected(None);
        callback.notify(ConnectionErrorNotification {
            kind: ConnectionErrorNotificationKind::ServerMaintenance,
            additional_info: None,
        });

        assert_eq!(
            *recording.disconnects.lock(),
            vec![Some(SHUTDOWN_REASON.to_owned())]
        );
        assert_eq!(*recording.notifications.lock(), vec![]);
    }

    #[test_log::test]
    fn test_explicit_shutdown() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
        let callback = RecordedCallback::default();
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

        for e in &errors_to_emit {
            server_config.send_blocking(Command::Send(e.clone()));
        }

        wait_for(|| callback.notifications.lock().len() == errors_to_emit.len());

        *callback.disconnect_delay.lock() = Duration::from_millis(500);
        connection.shutdown().unwrap();

        // No need for `wait_for` because `shutdown` should have already waited
        // until the end of the event processing task which calls `disconnected`
        // on the callback.
        assert!(
            !callback.disconnects.lock().is_empty(),
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
            *callback.disconnects.lock(),
            vec![Some(SHUTDOWN_REASON.to_owned())]
        );

        // `shutdown` should be idempotent
        assert_matches!(connection.shutdown(), Ok(()));
    }

    #[test_log::test]
    fn test_implicit_shutdown() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
        let callback = RecordedCallback::default();
        let connection = connect_to_test_server(&server_config, callback.clone());

        let error = ConnectionError {
            code: EnsProtoError::Unauthenticated as i32,
            additional_info: None,
        };

        server_config.send_blocking(Command::Send(error));

        wait_for(|| callback.notifications.lock().len() == 1);

        drop(connection);

        // `drop` doesn't wait so we need to
        wait_for(|| !callback.disconnects.lock().is_empty());

        let notifications = callback.notifications.lock();
        assert_eq!(
            *notifications,
            vec![ConnectionErrorNotification {
                kind: ConnectionErrorNotificationKind::Unauthenticated,
                additional_info: None,
            }]
        );

        assert_eq!(*callback.disconnects.lock(), vec![None]);
    }

    #[test_log::test]
    fn test_shutdown_called_by_callback() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
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

        for e in &errors_to_emit {
            server_config.send_blocking(Command::Send(e.clone()));
        }

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
            Some(Some(SHUTDOWN_REASON.to_owned()))
        );
    }

    #[test_log::test]
    fn test_connect_fails_when_key_material_is_incorrect() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
        let callback = RecordedCallback::default();
        let connection = connect_to_test_server_with_keys(
            &server_config,
            Keys {
                local_private_key: Hidden(MALFORMED_PRIVATE_KEY.to_vec()),
                vpn_public_key: Hidden(server_config.public_key.to_vec()),
                kind: crate::KeyKind::NordLynx,
            },
            callback.clone(),
        );

        assert_matches!(connection, Err(EnsError::UnknownError { reason }) if reason.contains("key conversion failed"));
    }

    #[test_log::test]
    fn test_disconnect_reported_when_server_gracefully_closes_the_stream() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
        let vpn_port = server_config.port;
        let callback = RecordedCallback::default();
        let connection = connect_to_test_server(&server_config, callback.clone());

        let error = ConnectionError {
            code: EnsProtoError::ServerMaintenance as i32,
            additional_info: Some("planned maintenance".to_owned()),
        };

        server_config.send_blocking(Command::Send(error));

        wait_for(|| callback.notifications.lock().len() == 1);

        server_config.send_blocking(Command::End);

        let reason = wait_for_disconnect_reason(&callback).unwrap();

        assert_eq!(
            reason,
            format!("'http://127.0.0.1:{vpn_port}' closed the grpc stream")
        );
        assert_eq!(
            *callback.notifications.lock(),
            vec![ConnectionErrorNotification {
                kind: ConnectionErrorNotificationKind::ServerMaintenance,
                additional_info: Some("planned maintenance".to_owned()),
            }]
        );

        // Safe to call multiple times; subsequent calls are no-ops.
        assert_matches!(connection.shutdown(), Ok(()));
        assert_matches!(connection.shutdown(), Ok(()));

        let disconnects = callback.disconnects.lock().clone();
        assert_eq!(
            disconnects,
            vec![Some(format!(
                "'http://127.0.0.1:{vpn_port}' closed the grpc stream"
            ))],
        );
    }

    #[test_log::test]
    fn test_disconnect_reported_once_when_a_finished_connection_is_dropped() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));
        let vpn_port = server_config.port;
        let callback = RecordedCallback::default();
        let connection = connect_to_test_server(&server_config, callback.clone());
        let id = connection.id;

        server_config.send_blocking(Command::End);

        let reason = wait_for_disconnect_reason(&callback).unwrap();
        assert_eq!(
            reason,
            format!("'http://127.0.0.1:{vpn_port}' closed the grpc stream")
        );
        assert_eq!(0, tracked_connections(&[id]));

        drop(connection);

        assert_eq!(*callback.disconnects.lock(), vec![Some(reason)]);
    }

    #[test_log::test]
    fn test_active_connections_do_not_grow_with_every_reconnect() {
        run_init();

        let runtime = get_runtime().unwrap();
        let server_config = runtime.block_on(spawn_authenticating_server(global_user_agent()));

        let mut ids = Vec::new();

        for _ in 0..RECONNECT_COUNT {
            let callback = RecordedCallback::default();
            let connection = connect_to_test_server(&server_config, callback.clone());
            ids.push(connection.id);

            assert_eq!(tracked_connections(&ids), 1);

            drop(connection);

            // The entry is dropped together with the event processing task, so
            // it doesn't disappear immediately.
            wait_for(|| tracked_connections(&ids) == 0);
        }

        assert_eq!(tracked_connections(&ids), 0,);
    }
}
