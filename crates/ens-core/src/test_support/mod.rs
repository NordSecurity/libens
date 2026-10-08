#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_wraps)]

mod tls;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Once},
    time::{Duration, Instant},
};

use bstr::ByteSlice;
use ens_core::{
    connect, Authentication, Config, Connection, ConnectionErrorNotification, EnsError,
    ErrorNotificationCallback, Hidden, KeyKind, Keys, LogCallback, LogLevel,
};
use ens_stub::ExpectedAuth;
use llt_proto::ens::{ConnectionError, Error as EnsProtoError};
use parking_lot::Mutex;
use telio_crypto::SecretKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    select,
    sync::watch,
};

pub use ens_core::SHUTDOWN_REASON;
pub use ens_stub::{Command, ServerConfig};
pub use tls::*;

const TEST_APP_VERSION: &str = "tests";
const ANY_LOCAL_PORT: &str = "127.0.0.1:0";
const RELAY_BUFFER_SIZE: usize = 4096;
const MAX_WAIT_TIME: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const CALLBACK_PANIC_MESSAGE: &str = "test callback panic";

static INIT: Once = Once::new();

pub fn run_init() {
    INIT.call_once(|| ens_core::init(TEST_APP_VERSION.to_owned()).unwrap());
}

pub async fn spawn_server() -> ServerConfig {
    ens_stub::spawn_server(ExpectedAuth::any_nordlynx(), None)
        .await
        .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayMode {
    Forward,

    // Connections accepted before the switch stay open but carry no traffic.
    // Connections accepted afterwards forward normally.
    Silent,

    // Connections are accepted and reset at once, so the port stays taken.
    Refuse,

    // Connections accepted afterwards go to this port instead of the server.
    Redirect(u16),
}

#[derive(Clone, Default)]
pub struct Wire {
    pub to_server: Vec<u8>,
    pub to_client: Vec<u8>,
}

impl Wire {
    pub fn contains(&self, needle: &str) -> bool {
        self.to_server.contains_str(needle) || self.to_client.contains_str(needle)
    }
}

pub struct TcpRelay {
    pub port: u16,
    mode_tx: watch::Sender<RelayMode>,
    wire: Arc<Mutex<Wire>>,
}

impl TcpRelay {
    pub async fn spawn(server_port: u16) -> Self {
        let listener = TcpListener::bind(ANY_LOCAL_PORT).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mode_tx, mode_rx) = watch::channel(RelayMode::Forward);
        let wire = Arc::new(Mutex::new(Wire::default()));

        tokio::spawn(relay_loop(listener, server_port, mode_rx, wire.clone()));

        Self {
            port: addr.port(),
            mode_tx,
            wire,
        }
    }

    pub fn set_mode(&self, mode: RelayMode) {
        self.mode_tx.send(mode).unwrap();
    }

    pub fn wire(&self) -> Wire {
        self.wire.lock().clone()
    }
}

async fn relay_loop(
    listener: TcpListener,
    server_port: u16,
    mut mode_rx: watch::Receiver<RelayMode>,
    wire: Arc<Mutex<Wire>>,
) {
    loop {
        let client = select! {
            accepted = listener.accept() => accepted.unwrap().0,
            changed = mode_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
        };
        let mode_at_accept = *mode_rx.borrow();
        if mode_at_accept == RelayMode::Refuse {
            client.set_zero_linger().unwrap();
            continue;
        }

        let target_port = match mode_at_accept {
            RelayMode::Redirect(port) => port,
            _ => server_port,
        };
        let server = TcpStream::connect((Ipv4Addr::LOCALHOST, target_port))
            .await
            .unwrap();

        let (client_rx, client_tx) = client.into_split();
        let (server_rx, server_tx) = server.into_split();
        tokio::spawn(run_pipe(
            server_rx,
            client_tx,
            mode_at_accept,
            mode_rx.clone(),
            wire.clone(),
            Direction::ToClient,
        ));
        tokio::spawn(run_pipe(
            client_rx,
            server_tx,
            mode_at_accept,
            mode_rx.clone(),
            wire.clone(),
            Direction::ToServer,
        ));
    }
}

#[derive(Clone, Copy)]
enum Direction {
    ToServer,
    ToClient,
}

async fn run_pipe(
    mut rx: OwnedReadHalf,
    mut tx: OwnedWriteHalf,
    mode_at_accept: RelayMode,
    mut mode_rx: watch::Receiver<RelayMode>,
    wire: Arc<Mutex<Wire>>,
    direction: Direction,
) {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    loop {
        let read = select! {
            read = rx.read(&mut buf) => read,
            _ = mode_rx.wait_for(|m| *m == RelayMode::Refuse) => break,
        };
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        let silenced =
            mode_at_accept == RelayMode::Forward && *mode_rx.borrow() == RelayMode::Silent;
        if silenced {
            continue;
        }

        {
            let mut wire = wire.lock();
            let captured = match direction {
                Direction::ToServer => &mut wire.to_server,
                Direction::ToClient => &mut wire.to_client,
            };
            captured.extend_from_slice(&buf[..n]);
        }

        if tx.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum PanicAt {
    #[default]
    Never,
    Notify,
    Disconnected,
}

#[derive(Default)]
pub struct Recording {
    pub notifications: Mutex<Vec<ConnectionErrorNotification>>,

    // The reason of every `disconnected` call, in the order they arrived. The
    // udl documents `disconnected` as called at most once per `Connection`, so
    // the tests assert on the whole vector and not just on the last entry.
    pub disconnects: Mutex<Vec<Option<String>>>,

    // Simulate `disconnected` being slow
    pub disconnect_delay: Mutex<Duration>,

    pub notify_delay: Mutex<Duration>,

    pub panic_at: Mutex<PanicAt>,
}

#[derive(Clone, Default)]
pub struct RecordedCallback(Arc<Recording>);

impl std::ops::Deref for RecordedCallback {
    type Target = Recording;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl RecordedCallback {
    pub fn infos(&self) -> Vec<Option<String>> {
        self.0
            .notifications
            .lock()
            .iter()
            .map(|n| n.additional_info.clone())
            .collect()
    }

    fn panic_if(&self, stage: PanicAt) {
        let panic_at = *self.0.panic_at.lock();
        if panic_at != stage {
            return;
        }
        panic!("{CALLBACK_PANIC_MESSAGE}");
    }
}

impl ErrorNotificationCallback for RecordedCallback {
    fn notify(&self, notification: ConnectionErrorNotification) {
        let delay = *self.0.notify_delay.lock();
        std::thread::sleep(delay);
        self.0.notifications.lock().push(notification);
        self.panic_if(PanicAt::Notify);
    }

    fn disconnected(&self, reason: Option<String>) {
        let delay = *self.0.disconnect_delay.lock();
        std::thread::sleep(delay);
        self.0.disconnects.lock().push(reason);
        self.panic_if(PanicAt::Disconnected);
    }
}

pub fn test_auth(server_config: &ServerConfig) -> Authentication {
    Authentication::WithKeys {
        keys: Keys {
            local_private_key: Hidden(SecretKey::gen().to_vec()),
            vpn_public_key: Hidden(server_config.public_key.to_vec()),
            kind: KeyKind::NordLynx,
        },
    }
}

pub fn error(code: EnsProtoError, info: &str) -> Command {
    Command::Send(ConnectionError {
        code: code as i32,
        additional_info: Some(info.to_owned()),
    })
}

pub fn maintenance(info: &str) -> Command {
    error(EnsProtoError::ServerMaintenance, info)
}

pub fn connect_to_test_server(
    server_config: &ServerConfig,
    callback: impl ErrorNotificationCallback + 'static,
) -> Arc<Connection> {
    connect_to_test_server_with_auth(server_config, test_auth(server_config), callback).unwrap()
}

pub fn connect_to_test_server_with_auth(
    server_config: &ServerConfig,
    auth: Authentication,
    callback: impl ErrorNotificationCallback + 'static,
) -> Result<Arc<Connection>, EnsError> {
    connect_to_test_server_with_config(server_config, auth, callback, Config::new())
}

pub fn connect_to_test_server_with_config(
    server_config: &ServerConfig,
    auth: Authentication,
    callback: impl ErrorNotificationCallback + 'static,
    config: Config,
) -> Result<Arc<Connection>, EnsError> {
    connect_to_port(server_config.port, server_config, auth, callback, config)
}

pub fn connect_to_port(
    port: u16,
    server_config: &ServerConfig,
    auth: Authentication,
    callback: impl ErrorNotificationCallback + 'static,
    config: Config,
) -> Result<Arc<Connection>, EnsError> {
    config.set_root_certificate_override(Some(server_config.tls_config.ca_cert.der().to_vec()));

    connect_local(port, auth, callback, config)
}

pub fn connect_local(
    port: u16,
    auth: Authentication,
    callback: impl ErrorNotificationCallback + 'static,
    config: Config,
) -> Result<Arc<Connection>, EnsError> {
    connect(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        None,
        auth,
        Box::new(callback),
        Arc::new(config),
    )
}

#[track_caller]
pub fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + MAX_WAIT_TIME;
    loop {
        if predicate() {
            return;
        }
        assert!(Instant::now() < deadline, "Timed out in wait_for");
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[track_caller]
pub fn wait_for_disconnect_reason(callback: &RecordedCallback) -> Option<String> {
    let mut reason = None;
    wait_for(|| {
        reason = callback.disconnects.lock().first().cloned();
        reason.is_some()
    });
    reason.flatten()
}

pub type LogEntry = (LogLevel, String);

#[derive(Clone, Default)]
pub struct RecordedLogCallback(Arc<Mutex<Vec<LogEntry>>>);

impl RecordedLogCallback {
    pub fn entries(&self) -> Vec<LogEntry> {
        self.0.lock().clone()
    }

    pub fn received(&self, text: &str) -> bool {
        self.entries().iter().any(|(_, m)| m.contains(text))
    }
}

impl LogCallback for RecordedLogCallback {
    fn log(&self, log_level: LogLevel, message: String) {
        self.0.lock().push((log_level, message));
    }
}
