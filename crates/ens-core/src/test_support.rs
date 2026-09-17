#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_wraps)]

use std::{
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    process::{Child, ChildStderr, ChildStdout, Command as ProcessCommand, Stdio},
    str::SplitWhitespace,
    sync::{
        mpsc::{self, Sender},
        Arc, Once,
    },
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use ens_core::{
    connect, Authentication, Config, Connection, ConnectionErrorNotification, EnsError,
    ErrorNotificationCallback, Hidden, KeyKind, Keys, LogCallback, LogLevel,
};
use ens_stub::{ExpectedAuth, ServerType};
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

const TEST_APP_VERSION: &str = "tests";
const ANY_LOCAL_PORT: &str = "127.0.0.1:0";
const RELAY_BUFFER_SIZE: usize = 4096;
const MAX_WAIT_TIME: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const ECH_STUB_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/echstub");
const ECH_STUB_START_TIMEOUT: Duration = Duration::from_secs(120);
const ECH_STUB_READY: &str = "ready";
const ECH_STUB_HANDSHAKE: &str = "handshake";
const ECH_STUB_NONE: &str = "-";
const ECH_STUB_KEYLOG_ENV: &str = "ECH_STUB_KEYLOG";
const ECH_STUB_LOG_TARGET: &str = "echstub";
const SLOG_TIME_KEY: &str = "time=";
const SLOG_LEVEL_KEY: &str = "level=";
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

pub async fn spawn_plain_server() -> ServerConfig {
    ens_stub::spawn_server_of_type(ExpectedAuth::any_nordlynx(), None, ServerType::Plain)
        .await
        .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchMode {
    On,
    Off,
}

impl EchMode {
    fn flag(self) -> &'static str {
        match self {
            EchMode::On => "on",
            EchMode::Off => "off",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub accepted: bool,
    pub sni_seen: Option<String>,
    pub outer_sni: Option<String>,
}

struct EchStubReady {
    port: u16,
    ca_der: Vec<u8>,
    ech_config_list: Vec<u8>,
}

pub struct GoEchStub {
    child: Child,
    ready: EchStubReady,
    handshakes: Arc<Mutex<Vec<Handshake>>>,
}

impl GoEchStub {
    pub fn spawn(upstream_port: u16, public_name: &str, ech: EchMode) -> Self {
        let upstream = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, upstream_port));
        let mut command = ProcessCommand::new("go");
        command
            .args(["run", "."])
            .args(["-upstream", &upstream.to_string()])
            .args(["-public-name", public_name])
            .args(["-ech", ech.flag()])
            .arg("-v");
        if let Some(path) = std::env::var_os(ECH_STUB_KEYLOG_ENV) {
            command.arg("-keylog").arg(path);
        }

        let mut child = command
            .current_dir(ECH_STUB_DIR)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("ECH tests need go 1.24+ on PATH: {e}"));

        // Spawned from the test thread so libtest captures the forwarded lines
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || forward_ech_stub_stderr(stderr));

        let stdout = child.stdout.take().unwrap();
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let recorded = handshakes.clone();
        std::thread::spawn(move || read_ech_stub_output(stdout, &ready_tx, &recorded));

        let ready = ready_rx
            .recv_timeout(ECH_STUB_START_TIMEOUT)
            .expect("echstub did not report `ready`");

        Self {
            child,
            ready,
            handshakes,
        }
    }

    pub fn port(&self) -> u16 {
        self.ready.port
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ready.ca_der
    }

    pub fn ech_config_list(&self) -> &[u8] {
        &self.ready.ech_config_list
    }

    pub fn handshakes(&self) -> Vec<Handshake> {
        self.handshakes.lock().clone()
    }

    // Returns what arrived once `count` handshakes are in or the wait runs out,
    // so the caller's assertion reports the actual list instead of a timeout.
    pub fn wait_for_handshakes(&self, count: usize) -> Vec<Handshake> {
        let deadline = Instant::now() + MAX_WAIT_TIME;
        while self.handshakes.lock().len() < count && Instant::now() < deadline {
            std::thread::sleep(POLL_INTERVAL);
        }
        self.handshakes()
    }
}

impl Drop for GoEchStub {
    fn drop(&mut self) {
        // The stub exits on stdin EOF, `go run` would leave it behind on kill
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn forward_ech_stub_stderr(stderr: ChildStderr) {
    for line in BufReader::new(stderr).lines() {
        let Ok(line) = line else {
            return;
        };
        let (level, message) = parse_slog_line(&line);
        log::log!(target: ECH_STUB_LOG_TARGET, level, "{message}");
    }
}

fn parse_slog_line(line: &str) -> (log::Level, &str) {
    let without_time = match line.split_once(' ') {
        Some((time, rest)) if time.starts_with(SLOG_TIME_KEY) => rest,
        _ => line,
    };
    match without_time
        .strip_prefix(SLOG_LEVEL_KEY)
        .and_then(|l| l.split_once(' '))
    {
        Some((level, message)) => (slog_level(level), message),
        None => (log::Level::Warn, without_time),
    }
}

fn slog_level(name: &str) -> log::Level {
    match name {
        "DEBUG" => log::Level::Debug,
        "INFO" => log::Level::Info,
        "WARN" => log::Level::Warn,
        _ => log::Level::Error,
    }
}

fn read_ech_stub_output(
    stdout: ChildStdout,
    ready_tx: &Sender<EchStubReady>,
    handshakes: &Mutex<Vec<Handshake>>,
) {
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else {
            return;
        };

        let mut fields = line.split_whitespace();
        match fields.next() {
            Some(ECH_STUB_READY) => {
                let _ = ready_tx.send(parse_ech_stub_ready(fields));
            }
            Some(ECH_STUB_HANDSHAKE) => handshakes.lock().push(parse_handshake(fields)),
            _ => panic!("unexpected echstub output: {line}"),
        }
    }
}

fn parse_ech_stub_ready(mut fields: SplitWhitespace) -> EchStubReady {
    let port = fields.next().unwrap().parse().unwrap();
    let ca_der = STANDARD.decode(fields.next().unwrap()).unwrap();
    let ech_config_list = match fields.next().unwrap() {
        ECH_STUB_NONE => vec![],
        encoded => STANDARD.decode(encoded).unwrap(),
    };

    EchStubReady {
        port,
        ca_der,
        ech_config_list,
    }
}

fn parse_handshake(mut fields: SplitWhitespace) -> Handshake {
    let accepted = fields.next().unwrap().parse().unwrap();
    let sni_seen = parse_name(fields.next().unwrap());
    let outer_sni = parse_name(fields.next().unwrap());

    Handshake {
        accepted,
        sni_seen,
    }
}

fn parse_name(field: &str) -> Option<String> {
    match field {
        ECH_STUB_NONE => None,
        name => Some(name.to_owned()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayMode {
    Forward,

    // Connections accepted before the switch stay open but carry no traffic.
    // Connections accepted afterwards forward normally.
    Silent,

    Refuse,

    // Connections accepted afterwards go to this port instead of the server.
    Redirect(u16),
}

pub struct TcpRelay {
    pub port: u16,
    mode_tx: watch::Sender<RelayMode>,
}

impl TcpRelay {
    pub async fn spawn(server_port: u16) -> Self {
        let listener = TcpListener::bind(ANY_LOCAL_PORT).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mode_tx, mode_rx) = watch::channel(RelayMode::Forward);

        tokio::spawn(relay_loop(listener, addr, server_port, mode_rx));

        Self {
            port: addr.port(),
            mode_tx,
        }
    }

    pub fn set_mode(&self, mode: RelayMode) {
        self.mode_tx.send(mode).unwrap();
    }
}

async fn relay_loop(
    mut listener: TcpListener,
    addr: SocketAddr,
    server_port: u16,
    mut mode_rx: watch::Receiver<RelayMode>,
) {
    loop {
        loop {
            let client = select! {
                accepted = listener.accept() => accepted.unwrap().0,
                _ = mode_rx.wait_for(|m| *m == RelayMode::Refuse) => break,
            };
            let mode_at_accept = *mode_rx.borrow();
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
            ));
            tokio::spawn(run_pipe(
                client_rx,
                server_tx,
                mode_at_accept,
                mode_rx.clone(),
            ));
        }

        drop(listener);
        if mode_rx.wait_for(|m| *m != RelayMode::Refuse).await.is_err() {
            return;
        }
        listener = TcpListener::bind(addr).await.unwrap();
    }
}

async fn run_pipe(
    mut rx: OwnedReadHalf,
    mut tx: OwnedWriteHalf,
    mode_at_accept: RelayMode,
    mut mode_rx: watch::Receiver<RelayMode>,
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
