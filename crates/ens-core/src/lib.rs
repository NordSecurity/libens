#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#![allow(clippy::missing_errors_doc)]

mod logging;

use std::{
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::{atomic::AtomicBool, Arc},
};
use telio_sockets::{protector::make_external_protector, NativeProtector, SocketPool};
use thiserror::Error;

use crate::logging::LogCallbackHolder;

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
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub trait LogCallback: Send + Sync {
    fn log(&self, log_level: LogLevel, message: String);
}

pub fn set_log_callback(max_level: LogLevel, callback: Box<dyn LogCallback>) -> Result<()> {
    let callback = LogCallbackHolder::new(callback);
    logging::set_log_callback(max_level, callback)
}

#[must_use]
pub fn get_memory_usage() -> u64 {
    todo!()
}

#[must_use]
pub fn get_version() -> String {
    todo!()
}

/// Initialize the library. Needs to be called before any other function is called.
pub fn init() -> Result<()> {
    let was_initialized = IS_INITIALIZED.swap(true, std::sync::atomic::Ordering::Relaxed);
    if was_initialized {
        return Err(EnsError::AlreadyInitialized);
    }
    Ok(())
}

/// Deinitializes the library. After calling this, calls to other functions
/// will fail.
pub fn deinit() -> Result<()> {
    let was_initialized = IS_INITIALIZED.swap(false, std::sync::atomic::Ordering::Relaxed);
    if !was_initialized {
        return Err(EnsError::NotInitialized {
            reason: "deinit".to_owned(),
        });
    }
    Ok(())
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

pub fn connect(
    _ip: SocketAddr,
    protect_cb: Option<Box<dyn ProtectCallback>>,
    _authentication: Authentication,
    _callback: Box<dyn ErrorNotificationCallback>,
) -> Result<Arc<Connection>> {
    let protect: Option<telio_sockets::Protect> = match protect_cb {
        Some(protect) => {
            let protect = AssertUnwindSafe(protect);
            #[allow(clippy::useless_conversion)]
            Some(Arc::new(move |fd| match fd.try_into() {
                Ok(fd) => {
                    let protect_res = protect.protect(fd);
                    if let Err(err) = protect_res {
                        eprintln!("Could not call protect callback due to {err:?}");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to convert file discriptor: {e}");
                }
            }))
        }
        _ => None,
    };

    let _socket_pool = Arc::new({
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

    todo!()
}

pub struct Connection {}

impl Connection {
    pub fn shutdown(&self) -> Result<()> {
        todo!()
    }
}
