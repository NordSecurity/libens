#![allow(dead_code)]
#![allow(clippy::unnecessary_wraps)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Once},
    time::{Duration, Instant},
};

use async_channel::{unbounded, Receiver as AsyncReceiver, Sender as AsyncSender};
use ens_core::{
    connect, Authentication, Config, Connection, ConnectionErrorNotification, EnsError,
    ErrorNotificationCallback, Hidden, KeyKind, Keys,
};
use llt_proto::ens::{
    ens_server::{self, EnsServer},
    login_server::{self, LoginServer},
    ChallengeRequest, ChallengeResponse, ConnectionError, ConnectionErrorRequest,
};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, SanType,
};
use telio_crypto::{PublicKey, SecretKey, SharedSecret};
use tokio::{net::TcpListener, sync::mpsc::channel};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{
    service::Interceptor,
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use uuid::Uuid;

pub const SHUTDOWN_REASON: &str = "shutdown";

const TEST_APP_VERSION: &str = "tests";
const CA_COMMON_NAME: &str = "Test CA";
const CA_ORGANIZATION_NAME: &str = "Test Org";
const LOCALHOST: &str = "localhost";
const ANY_LOCAL_PORT: &str = "127.0.0.1:0";
const ERROR_STREAM_CHANNEL_SIZE: usize = 1;
const MAX_WAIT_TIME: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

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
}

impl ServerConfig {
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
        challenges: Mutex::new(HashSet::default()),
        vpn_server_private_key,
    }));

    let ens_service = EnsServer::with_interceptor(stub.clone(), make_interceptor(stub.clone()));
    let login_service = LoginServer::new(stub);

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
    }
}

fn accept_any_authentication(request: Request<()>) -> Result<Request<()>, Status> {
    Ok(request)
}

#[derive(Default)]
pub struct Recording {
    pub notifications: Mutex<Vec<ConnectionErrorNotification>>,

    // Outer Option: whether `disconnected` was called at all.
    // Inner Option<String>: the reason passed in.
    #[allow(clippy::option_option)]
    pub disconnected: Mutex<Option<Option<String>>>,

    // Simulate `disconnected` being slow
    pub disconnect_delay: Mutex<Duration>,
}

#[derive(Clone, Default)]
pub struct RecordedCallback(Arc<Recording>);

impl std::ops::Deref for RecordedCallback {
    type Target = Recording;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ErrorNotificationCallback for RecordedCallback {
    fn notify(&self, notification: ConnectionErrorNotification) {
        self.0.notifications.lock().push(notification);
    }

    fn disconnected(&self, reason: Option<String>) {
        let delay = *self.0.disconnect_delay.lock();
        std::thread::sleep(delay);
        *self.0.disconnected.lock() = Some(reason);
    }
}

pub fn connect_to_test_server(
    server_config: &ServerConfig,
    callback: impl ErrorNotificationCallback + 'static,
) -> Arc<Connection> {
    connect_to_test_server_with_keys(
        server_config,
        Keys {
            local_private_key: Hidden(SecretKey::gen().to_vec()),
            vpn_public_key: Hidden(server_config.public_key.to_vec()),
            kind: KeyKind::NordLynx,
        },
        callback,
    )
    .unwrap()
}

pub fn connect_to_test_server_with_keys(
    server_config: &ServerConfig,
    keys: Keys,
    callback: impl ErrorNotificationCallback + 'static,
) -> Result<Arc<Connection>, EnsError> {
    let config = Config::new();
    config.set_root_certificate_override(Some(server_config.tls_config.ca_cert.der().to_vec()));

    connect(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, server_config.port)),
        None,
        Authentication::Keys { keys },
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
        reason = callback.disconnected.lock().clone();
        reason.is_some()
    });
    reason.flatten()
}
