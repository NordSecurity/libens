#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_wraps)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Once,
    },
    time::{Duration, Instant},
};

use async_channel::{unbounded, Receiver as AsyncReceiver, Sender as AsyncSender};
use ens_core::{
    connect, Authentication, Config, Connection, ConnectionErrorNotification, EnsError,
    ErrorNotificationCallback, Hidden, KeyKind, Keys, LogCallback, LogLevel,
};
use llt_proto::ens::{
    ens_server::{self, EnsServer},
    login_server::{self, LoginServer},
    ChallengeRequest, ChallengeResponse, ConnectionError, ConnectionErrorRequest,
    Error as EnsProtoError,
};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, SanType,
};
use telio_crypto::{PublicKey, SecretKey, SharedSecret};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    select,
    sync::{mpsc::channel, watch},
};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{
    service::Interceptor,
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use uuid::Uuid;

pub use ens_core::SHUTDOWN_REASON;

const TEST_APP_VERSION: &str = "tests";
const CA_COMMON_NAME: &str = "Test CA";
const CA_ORGANIZATION_NAME: &str = "Test Org";
const LOCALHOST: &str = "localhost";
const ANY_LOCAL_PORT: &str = "127.0.0.1:0";
const RELAY_BUFFER_SIZE: usize = 4096;
const ERROR_STREAM_CHANNEL_SIZE: usize = 1;
const MAX_WAIT_TIME: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const CALLBACK_PANIC_MESSAGE: &str = "test callback panic";

static INIT: Once = Once::new();

pub fn run_init() {
    INIT.call_once(|| ens_core::init(TEST_APP_VERSION.to_owned()).unwrap());
}

#[derive(Debug)]
pub enum Command {
    Send(ConnectionError),
    Error(Status),
    End,
}

// Root CA and a leaf cert issued by it
#[derive(Debug)]
pub struct TlsConfig {
    pub ca_cert: Certificate,
    pub leaf_cert: Certificate,
    leaf_key_pem: String,
}

impl TlsConfig {
    pub fn new() -> Self {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, CA_COMMON_NAME);
        ca_dn.push(DnType::OrganizationName, CA_ORGANIZATION_NAME);
        ca_params.distinguished_name = ca_dn;

        let ca_key_pair = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
        let issuer = Issuer::new(ca_params, ca_key_pair);

        let mut leaf_params = CertificateParams::default();
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, LOCALHOST);
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.subject_alt_names = vec![
            SanType::DnsName(LOCALHOST.parse().unwrap()),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];

        let leaf_key_pair = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key_pair, &issuer).unwrap();

        TlsConfig {
            ca_cert,
            leaf_cert,
            leaf_key_pem: leaf_key_pair.serialize_pem(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new()
    }
}

struct StubState {
    command_rx: AsyncReceiver<Command>,
    streams: AtomicUsize,
    challenges: Mutex<HashSet<Uuid>>,
    vpn_server_private_key: SecretKey,
}

#[derive(Clone)]
pub struct GrpcStub(Arc<StubState>);

impl GrpcStub {
    pub fn take_challenge(&self, challenge: &Uuid) -> bool {
        self.0.challenges.lock().take(challenge).is_some()
    }

    pub fn shared_secret(&self, client_public_key: &PublicKey) -> SharedSecret {
        self.0.vpn_server_private_key.ecdh(client_public_key)
    }
}

#[tonic::async_trait]
impl ens_server::Ens for GrpcStub {
    type ConnectionErrorsStream = ReceiverStream<Result<ConnectionError, Status>>;

    async fn connection_errors(
        &self,
        _request: Request<ConnectionErrorRequest>,
    ) -> Result<Response<Self::ConnectionErrorsStream>, Status> {
        self.0.streams.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = channel(ERROR_STREAM_CHANNEL_SIZE);

        let command_rx = self.0.command_rx.clone();
        tokio::spawn(async move {
            while let Ok(command) = command_rx.recv().await {
                let sent = match command {
                    Command::Send(e) => tx.send(Ok(e)).await,
                    Command::Error(status) => tx.send(Err(status)).await,
                    Command::End => break,
                };

                // The client might have dropped this stream already, e.g. after
                // reconnecting because of a keepalive timeout.
                if sent.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tonic::async_trait]
impl login_server::Login for GrpcStub {
    async fn get_challenge(
        &self,
        _request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let challenge = Uuid::new_v4();
        self.0.challenges.lock().insert(challenge);
        Ok(Response::new(ChallengeResponse {
            challenge: challenge.to_string(),
        }))
    }
}

pub struct ServerConfig {
    pub port: u16,
    pub public_key: PublicKey,
    pub command_tx: AsyncSender<Command>,
    pub tls_config: TlsConfig,
    stub: GrpcStub,
}

impl ServerConfig {
    pub fn streams(&self) -> usize {
        self.stub.0.streams.load(Ordering::SeqCst)
    }

    pub fn send_blocking(&self, command: Command) {
        self.command_tx.send_blocking(command).unwrap();
    }

    pub async fn send(&self, command: Command) {
        self.command_tx.send(command).await.unwrap();
    }

    pub async fn send_errors(&self, errors_to_emit: &[ConnectionError]) {
        for e in errors_to_emit {
            self.send(Command::Send(e.clone())).await;
        }
        self.send(Command::End).await;
    }
}

pub async fn spawn_server() -> ServerConfig {
    spawn_server_with_interceptor(|_| accept_any_authentication).await
}

pub async fn spawn_server_with_interceptor<I: Interceptor + Clone + Send + Sync + 'static>(
    make_interceptor: impl FnOnce(GrpcStub) -> I,
) -> ServerConfig {
    let vpn_server_private_key = SecretKey::gen();
    let public_key = vpn_server_private_key.public();

    let (command_tx, command_rx) = unbounded();
    let stub = GrpcStub(Arc::new(StubState {
        command_rx,
        streams: AtomicUsize::new(0),
        challenges: Mutex::new(HashSet::default()),
        vpn_server_private_key,
    }));

    let ens_service = EnsServer::with_interceptor(stub.clone(), make_interceptor(stub.clone()));
    let login_service = LoginServer::new(stub.clone());

    let tls_config = TlsConfig::new();
    let tonic_tls_config = ServerTlsConfig::new().identity(Identity::from_pem(
        tls_config.leaf_cert.pem(),
        &tls_config.leaf_key_pem,
    ));

    let listener = TcpListener::bind(ANY_LOCAL_PORT).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tonic_tls_config)
            .unwrap()
            .add_service(ens_service)
            .add_service(login_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    ServerConfig {
        port,
        public_key,
        command_tx,
        tls_config,
        stub,
    }
}

fn accept_any_authentication(request: Request<()>) -> Result<Request<()>, Status> {
    Ok(request)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayMode {
    Forward,

    // Connections accepted before the switch stay open but carry no traffic.
    // Connections accepted afterwards forward normally.
    Silent,

    Refuse,
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
            let server = TcpStream::connect((Ipv4Addr::LOCALHOST, server_port))
                .await
                .unwrap();
            let mode_at_accept = *mode_rx.borrow();

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
