//! ENS server stub shared by the tests of every supported language.
//!
//! The Rust tests link this library directly. Tests for the bindings will
//! drive the `ens-stub` binary built from the same code.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#![allow(clippy::missing_errors_doc)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_channel::{unbounded, Receiver as AsyncReceiver, Sender as AsyncSender};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use blake3::{derive_key, keyed_hash};
use http::{header::AUTHORIZATION, HeaderValue};
use log::{error, warn};
use parking_lot::Mutex;
use rand::distr::{Alphanumeric, SampleString};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, Issuer,
    KeyPair, SanType,
};
use telio_crypto::{PublicKey, SecretKey, SharedSecret};
use tokio::{net::TcpListener, select, sync::mpsc::channel};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{
    service::Interceptor,
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use uuid::Uuid;

use llt_proto::ens::{
    ens_server::{self, EnsServer},
    login_server::{self, LoginServer},
    ChallengeRequest, ChallengeResponse, ConnectionError, ConnectionErrorRequest,
};

const CA_COMMON_NAME: &str = "Test CA";
const CA_ORGANIZATION_NAME: &str = "Test Org";
const LOCALHOST: &str = "localhost";
const ANY_LOCAL_PORT: &str = "127.0.0.1:0";
const ERROR_STREAM_CHANNEL_SIZE: usize = 1;

const AUTHENTICATION_CONTEXT: &str = "ens-auth";
const AUTHENTICATION_KEY: &str = "authentication";
const NORD_VPN_PROTOCOL_KEY: &str = "nord-vpn-protocol";
const USER_AGENT_KEY: &str = "user-agent";

const NORDLYNX_PROTOCOL: &str = "nordlynx";
const NORDWHISPER_PROTOCOL: &str = "nordwhisper";
const OPENVPN_PROTOCOL: &str = "openvpn";

const PUBLIC_KEY_LEN: usize = 32;
const CHALLENGE_LEN: usize = 16;
const AUTHENTICATION_TAG_OFFSET: usize = PUBLIC_KEY_LEN + CHALLENGE_LEN;
const GENERATED_CREDENTIAL_LEN: usize = 10;

/// Errors returned while starting the stub
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The stub TLS certificates could not be generated
    #[error("Certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    /// The stub could not open its listening socket
    #[error("Listening socket failure: {0}")]
    Socket(#[from] std::io::Error),
    /// The grpc server rejected its configuration
    #[error("Grpc server failure: {0}")]
    Transport(#[from] tonic::transport::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// What the stub sends over the error notification stream
#[derive(Debug)]
pub enum Command {
    Send(ConnectionError),
    Error(Status),
    End,
}

/// The authentication material the stub expects from the client. Mirrors the
/// three schemas the real ENS server accepts.
#[derive(Clone, Debug)]
pub enum ExpectedAuth {
    /// Nordlynx clients answer a challenge with their key material. The
    /// answering key is pinned only when `client_public_key` is given.
    NordLynx {
        client_public_key: Option<PublicKey>,
    },
    NordWhisper {
        username: String,
        password: String,
    },
    OpenVpn {
        username: String,
        password: String,
    },
}

impl ExpectedAuth {
    /// Accepts any client that answers the challenge with a key pair of its own
    #[must_use]
    pub fn any_nordlynx() -> Self {
        Self::NordLynx {
            client_public_key: None,
        }
    }

    #[must_use]
    pub fn new_nordwhisper() -> Self {
        let (username, password) = generated_credentials();
        Self::NordWhisper { username, password }
    }

    #[must_use]
    pub fn new_openvpn() -> Self {
        let (username, password) = generated_credentials();
        Self::OpenVpn { username, password }
    }

    #[must_use]
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::NordLynx { .. } => NORDLYNX_PROTOCOL,
            Self::NordWhisper { .. } => NORDWHISPER_PROTOCOL,
            Self::OpenVpn { .. } => OPENVPN_PROTOCOL,
        }
    }

    /// The credentials a client has to send, for the schemas that use them
    #[must_use]
    pub fn credentials(&self) -> Option<(&str, &str)> {
        match self {
            Self::NordLynx { .. } => None,
            Self::NordWhisper { username, password } | Self::OpenVpn { username, password } => {
                Some((username, password))
            }
        }
    }
}

fn generated_credentials() -> (String, String) {
    let mut rng = rand::rng();
    (
        Alphanumeric.sample_string(&mut rng, GENERATED_CREDENTIAL_LEN),
        Alphanumeric.sample_string(&mut rng, GENERATED_CREDENTIAL_LEN),
    )
}

/// Root CA and a leaf cert issued by it
#[derive(Debug)]
pub struct TlsConfig {
    pub ca_cert: Certificate,
    pub leaf_cert: Certificate,
    leaf_key_pem: String,
}

impl TlsConfig {
    pub fn new() -> Result<Self> {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, CA_COMMON_NAME);
        ca_dn.push(DnType::OrganizationName, CA_ORGANIZATION_NAME);
        ca_params.distinguished_name = ca_dn;

        let ca_key_pair = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;
        let issuer = Issuer::new(ca_params, ca_key_pair);

        let mut leaf_params = CertificateParams::default();
        let mut leaf_dn = DistinguishedName::new();
        leaf_dn.push(DnType::CommonName, LOCALHOST);
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.subject_alt_names = vec![
            SanType::DnsName(LOCALHOST.parse()?),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];

        let leaf_key_pair = KeyPair::generate()?;
        let leaf_cert = leaf_params.signed_by(&leaf_key_pair, &issuer)?;

        Ok(TlsConfig {
            ca_cert,
            leaf_cert,
            leaf_key_pem: leaf_key_pair.serialize_pem(),
        })
    }
}

/// Handle to a running stub
pub struct ServerConfig {
    pub port: u16,
    pub public_key: PublicKey,
    pub tls_config: TlsConfig,
    command_tx: AsyncSender<Command>,
    stub: GrpcStub,
}

impl ServerConfig {
    /// How many error notification streams the stub has opened so far
    #[must_use]
    pub fn streams(&self) -> usize {
        self.stub.0.streams.load(Ordering::SeqCst)
    }

    /// Queues a command for the error notification stream. The commands are
    /// buffered, so they can be sent before the client connects.
    pub fn send_blocking(&self, command: Command) {
        if let Err(e) = self.command_tx.send_blocking(command) {
            error!("Stub is no longer running, dropping {:?}", e.into_inner());
        }
    }

    pub async fn send(&self, command: Command) {
        if let Err(e) = self.command_tx.send(command).await {
            error!("Stub is no longer running, dropping {:?}", e.into_inner());
        }
    }

    pub async fn send_errors(&self, errors_to_emit: &[ConnectionError]) {
        for e in errors_to_emit {
            self.send(Command::Send(e.clone())).await;
        }
        self.send(Command::End).await;
    }
}

/// Starts a stub verifying authentication the same way the real ENS server
/// does. The user agent is only verified when `expected_user_agent` is given.
pub async fn spawn_server(
    auth: ExpectedAuth,
    expected_user_agent: Option<HeaderValue>,
) -> Result<ServerConfig> {
    let vpn_server_private_key = SecretKey::gen();
    let public_key = vpn_server_private_key.public();

    let (command_tx, command_rx) = unbounded();
    let stub = GrpcStub(Arc::new(StubState {
        command_rx,
        streams: AtomicUsize::new(0),
        challenges: Mutex::new(HashSet::default()),
        vpn_server_private_key,
    }));

    let interceptor = CheckAuthenticationInterceptor {
        stub: stub.clone(),
        auth,
        expected_user_agent,
    };
    let ens_service = EnsServer::with_interceptor(stub.clone(), interceptor);
    let login_service = LoginServer::new(stub.clone());

    let tls_config = TlsConfig::new()?;
    let tonic_tls_config = ServerTlsConfig::new().identity(Identity::from_pem(
        tls_config.leaf_cert.pem(),
        &tls_config.leaf_key_pem,
    ));

    let listener = TcpListener::bind(ANY_LOCAL_PORT).await?;
    let port = listener.local_addr()?.port();

    let server = Server::builder()
        .tls_config(tonic_tls_config)?
        .add_service(ens_service)
        .add_service(login_service);

    tokio::spawn(async move {
        if let Err(e) = server
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
        {
            error!("Stub on port {port} stopped: {e}");
        }
    });

    Ok(ServerConfig {
        port,
        public_key,
        tls_config,
        command_tx,
        stub,
    })
}

struct StubState {
    command_rx: AsyncReceiver<Command>,
    streams: AtomicUsize,
    challenges: Mutex<HashSet<Uuid>>,
    vpn_server_private_key: SecretKey,
}

#[derive(Clone)]
struct GrpcStub(Arc<StubState>);

impl GrpcStub {
    fn take_challenge(&self, challenge: &Uuid) -> bool {
        self.0.challenges.lock().take(challenge).is_some()
    }

    fn shared_secret(&self, client_public_key: &PublicKey) -> SharedSecret {
        self.0.vpn_server_private_key.ecdh(client_public_key)
    }
}

#[tonic::async_trait]
impl ens_server::Ens for GrpcStub {
    type ConnectionErrorsStream = ReceiverStream<std::result::Result<ConnectionError, Status>>;

    async fn connection_errors(
        &self,
        _request: Request<ConnectionErrorRequest>,
    ) -> std::result::Result<Response<Self::ConnectionErrorsStream>, Status> {
        self.0.streams.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = channel(ERROR_STREAM_CHANNEL_SIZE);

        let command_rx = self.0.command_rx.clone();
        tokio::spawn(async move {
            loop {
                // Stop as soon as the client drops this stream, e.g. after
                // reconnecting because of a keepalive timeout, so that the
                // commands meant for the new stream are not consumed here.
                let command = select! {
                    () = tx.closed() => break,
                    command = command_rx.recv() => command,
                };

                let Ok(command) = command else {
                    break;
                };

                let sent = match command {
                    Command::Send(e) => tx.send(Ok(e)).await,
                    Command::Error(status) => tx.send(Err(status)).await,
                    Command::End => break,
                };

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
    ) -> std::result::Result<Response<ChallengeResponse>, Status> {
        let challenge = Uuid::new_v4();
        self.0.challenges.lock().insert(challenge);
        Ok(Response::new(ChallengeResponse {
            challenge: challenge.to_string(),
        }))
    }
}

#[derive(Clone)]
struct CheckAuthenticationInterceptor {
    stub: GrpcStub,
    auth: ExpectedAuth,
    expected_user_agent: Option<HeaderValue>,
}

impl Interceptor for CheckAuthenticationInterceptor {
    fn call(&mut self, req: Request<()>) -> std::result::Result<Request<()>, Status> {
        self.check(&req)
            .inspect_err(|e| warn!("Rejecting a request: {e}"))?;

        Ok(req)
    }
}

impl CheckAuthenticationInterceptor {
    fn check(&self, req: &Request<()>) -> std::result::Result<(), Status> {
        self.check_user_agent(req)?;
        self.check_authentication(req)?;
        check_protocol(req, self.auth.protocol_name())
    }

    fn check_user_agent(&self, req: &Request<()>) -> std::result::Result<(), Status> {
        let Some(expected) = &self.expected_user_agent else {
            return Ok(());
        };

        let received = req
            .metadata()
            .get(USER_AGENT_KEY)
            .and_then(|s| s.to_str().ok())
            .unwrap_or_default();

        // tonic appends its own version to the user-agent sent over wire
        if !received.starts_with(expected.to_str().unwrap_or_default()) {
            return Err(Status::unauthenticated(format!(
                "Expected user-agent {expected:?}, got {received:?}"
            )));
        }

        Ok(())
    }

    fn check_authentication(&self, req: &Request<()>) -> std::result::Result<(), Status> {
        match &self.auth {
            ExpectedAuth::NordLynx { client_public_key } => {
                self.check_challenge(req, client_public_key.as_ref())
            }
            ExpectedAuth::NordWhisper { username, password }
            | ExpectedAuth::OpenVpn { username, password } => {
                check_credentials(req, username, password)
            }
        }
    }

    fn check_challenge(
        &self,
        req: &Request<()>,
        expected_client_public_key: Option<&PublicKey>,
    ) -> std::result::Result<(), Status> {
        let authentication = req
            .metadata()
            .get(AUTHENTICATION_KEY)
            .ok_or_else(|| Status::unauthenticated("No valid auth token"))?;
        let decoded = BASE64_STANDARD
            .decode(authentication)
            .map_err(|e| Status::unauthenticated(format!("Auth token is not base64: {e}")))?;

        let (Some(client_public_key), Some(challenge)) = (
            decoded
                .get(..PUBLIC_KEY_LEN)
                .and_then(|k| <[u8; PUBLIC_KEY_LEN]>::try_from(k).ok())
                .map(PublicKey::new),
            decoded
                .get(PUBLIC_KEY_LEN..AUTHENTICATION_TAG_OFFSET)
                .and_then(|c| Uuid::from_slice(c).ok()),
        ) else {
            return Err(Status::unauthenticated("Malformed auth token"));
        };

        if !self.stub.take_challenge(&challenge) {
            return Err(Status::unauthenticated("Unknown auth token"));
        }

        let secret = self.stub.shared_secret(&client_public_key);
        if decoded[AUTHENTICATION_TAG_OFFSET..]
            != authentication_tag(&secret, &decoded[..AUTHENTICATION_TAG_OFFSET])
        {
            return Err(Status::unauthenticated("Challenge not authenticated"));
        }

        if expected_client_public_key.is_some_and(|expected| *expected != client_public_key) {
            return Err(Status::unauthenticated("Client with unknown nordlynx key"));
        }

        Ok(())
    }
}

fn check_credentials(
    req: &Request<()>,
    username: &str,
    password: &str,
) -> std::result::Result<(), Status> {
    let authorization = req
        .metadata()
        .get(AUTHORIZATION.as_str())
        .and_then(|a| a.to_str().ok())
        .ok_or_else(|| Status::unauthenticated(format!("Missing {AUTHORIZATION} in metadata")))?;

    let received = http_auth_basic::Credentials::from_header(authorization.to_owned())
        .map_err(|e| Status::unauthenticated(format!("Malformed {AUTHORIZATION}: {e}")))?;

    if received.user_id != username {
        return Err(Status::unauthenticated(format!(
            "Expected username {username}, got {}",
            received.user_id
        )));
    }

    if received.password != password {
        return Err(Status::unauthenticated("Incorrect password"));
    }

    Ok(())
}

fn check_protocol(req: &Request<()>, expected: &str) -> std::result::Result<(), Status> {
    let Some(protocol) = req.metadata().get(NORD_VPN_PROTOCOL_KEY) else {
        return Err(Status::unavailable(format!(
            "Missing {NORD_VPN_PROTOCOL_KEY} in metadata"
        )));
    };

    if protocol != expected {
        return Err(Status::unavailable(format!(
            "Incorrect {NORD_VPN_PROTOCOL_KEY} in metadata: {protocol:?}"
        )));
    }

    Ok(())
}

fn authentication_tag(secret: &SharedSecret, message: &[u8]) -> [u8; 32] {
    let key = derive_key(AUTHENTICATION_CONTEXT, secret);
    *keyed_hash(&key, message).as_bytes()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tonic::Code;

    use super::*;

    const TEST_USER_AGENT: HeaderValue = HeaderValue::from_static("test-agent");

    fn stub() -> GrpcStub {
        let (_command_tx, command_rx) = unbounded();
        GrpcStub(Arc::new(StubState {
            command_rx,
            streams: AtomicUsize::new(0),
            challenges: Mutex::new(HashSet::default()),
            vpn_server_private_key: SecretKey::gen(),
        }))
    }

    fn interceptor(
        stub: &GrpcStub,
        auth: ExpectedAuth,
        expected_user_agent: Option<HeaderValue>,
    ) -> CheckAuthenticationInterceptor {
        CheckAuthenticationInterceptor {
            stub: stub.clone(),
            auth,
            expected_user_agent,
        }
    }

    async fn issued_challenge(stub: &GrpcStub) -> Uuid {
        let response = login_server::Login::get_challenge(stub, Request::new(ChallengeRequest {}))
            .await
            .unwrap();
        Uuid::from_str(&response.into_inner().challenge).unwrap()
    }

    fn challenge_answer(
        stub: &GrpcStub,
        client_private_key: &SecretKey,
        challenge: Uuid,
    ) -> Vec<u8> {
        let server_public_key = stub.0.vpn_server_private_key.public();

        let mut answer = client_private_key.public().to_vec();
        answer.extend_from_slice(challenge.as_bytes());
        let tag = authentication_tag(&client_private_key.ecdh(&server_public_key), &answer);
        answer.extend_from_slice(&tag);

        answer
    }

    fn keys_request(answer: &[u8], protocol: &str) -> Request<()> {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTHENTICATION_KEY,
            BASE64_STANDARD.encode(answer).parse().unwrap(),
        );
        request
            .metadata_mut()
            .insert(NORD_VPN_PROTOCOL_KEY, protocol.parse().unwrap());

        request
    }

    fn credentials_request(username: &str, password: &str, protocol: &str) -> Request<()> {
        let header = http_auth_basic::Credentials::new(username, password).as_http_header();

        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(AUTHORIZATION.as_str(), header.parse().unwrap());
        request
            .metadata_mut()
            .insert(NORD_VPN_PROTOCOL_KEY, protocol.parse().unwrap());

        request
    }

    #[tokio::test]
    async fn a_challenge_can_be_answered_only_once() {
        let stub = stub();
        let answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);
        let mut interceptor = interceptor(&stub, ExpectedAuth::any_nordlynx(), None);

        assert!(interceptor
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .is_ok());

        let replayed = interceptor
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .unwrap_err();
        assert_eq!(replayed.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn a_challenge_the_stub_never_issued_is_rejected() {
        let stub = stub();
        let answer = challenge_answer(&stub, &SecretKey::gen(), Uuid::new_v4());

        let rejected = interceptor(&stub, ExpectedAuth::any_nordlynx(), None)
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn a_tampered_authentication_tag_is_rejected() {
        let stub = stub();
        let mut answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);
        *answer.last_mut().unwrap() ^= 1;

        let rejected = interceptor(&stub, ExpectedAuth::any_nordlynx(), None)
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn a_truncated_answer_is_rejected() {
        let stub = stub();
        let mut answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);
        answer.truncate(PUBLIC_KEY_LEN);

        let rejected = interceptor(&stub, ExpectedAuth::any_nordlynx(), None)
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn another_client_key_is_rejected_when_one_is_pinned() {
        let stub = stub();
        let answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);
        let pinned = ExpectedAuth::NordLynx {
            client_public_key: Some(SecretKey::gen().public()),
        };

        let rejected = interceptor(&stub, pinned, None)
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn the_pinned_client_key_is_accepted() {
        let stub = stub();
        let client_private_key = SecretKey::gen();
        let answer = challenge_answer(&stub, &client_private_key, issued_challenge(&stub).await);
        let pinned = ExpectedAuth::NordLynx {
            client_public_key: Some(client_private_key.public()),
        };

        assert!(interceptor(&stub, pinned, None)
            .call(keys_request(&answer, NORDLYNX_PROTOCOL))
            .is_ok());
    }

    #[tokio::test]
    async fn another_protocol_is_rejected() {
        let stub = stub();
        let answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);

        let rejected = interceptor(&stub, ExpectedAuth::any_nordlynx(), None)
            .call(keys_request(&answer, OPENVPN_PROTOCOL))
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unavailable);
    }

    #[tokio::test]
    async fn matching_credentials_are_accepted() {
        let stub = stub();
        let auth = ExpectedAuth::new_openvpn();
        let (username, password) = auth.credentials().unwrap();
        let request = credentials_request(username, password, OPENVPN_PROTOCOL);

        assert!(interceptor(&stub, auth.clone(), None).call(request).is_ok());
    }

    #[tokio::test]
    async fn a_wrong_password_is_rejected() {
        let stub = stub();
        let auth = ExpectedAuth::new_nordwhisper();
        let (username, _) = auth.credentials().unwrap();
        let request = credentials_request(username, "not the password", NORDWHISPER_PROTOCOL);

        let rejected = interceptor(&stub, auth.clone(), None)
            .call(request)
            .unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn a_missing_authorization_header_is_rejected() {
        let stub = stub();
        let auth = ExpectedAuth::new_openvpn();

        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(NORD_VPN_PROTOCOL_KEY, OPENVPN_PROTOCOL.parse().unwrap());

        let rejected = interceptor(&stub, auth, None).call(request).unwrap_err();
        assert_eq!(rejected.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn the_user_agent_is_verified_when_expected() {
        let stub = stub();
        let answer = challenge_answer(&stub, &SecretKey::gen(), issued_challenge(&stub).await);
        let mut interceptor =
            interceptor(&stub, ExpectedAuth::any_nordlynx(), Some(TEST_USER_AGENT));

        let mut accepted = keys_request(&answer, NORDLYNX_PROTOCOL);
        accepted
            .metadata_mut()
            .insert(USER_AGENT_KEY, "test-agent tonic/0.14".parse().unwrap());
        assert!(interceptor.call(accepted).is_ok());

        let mut rejected = keys_request(&answer, NORDLYNX_PROTOCOL);
        rejected
            .metadata_mut()
            .insert(USER_AGENT_KEY, "some-other-agent".parse().unwrap());
        assert_eq!(
            interceptor.call(rejected).unwrap_err().code(),
            Code::Unauthenticated
        );
    }
}
