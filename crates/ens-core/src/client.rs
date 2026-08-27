use std::{
    error::Error as _, net::IpAddr, num::NonZeroUsize, str::FromStr, sync::Arc, time::Duration,
};

use telio_crypto::{PublicKey, SecretKey, SharedSecret};
use telio_sockets::SocketPool;
use telio_utils::exponential_backoff::{self, Backoff};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use blake3::{derive_key, keyed_hash};
use http::{HeaderValue, Uri};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use rustls::{
    client::danger::ServerCertVerifier, crypto::CryptoProvider, pki_types::CertificateDer,
    ClientConfig, RootCertStore,
};
use tokio::{
    net::lookup_host,
    select,
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use tonic::{
    metadata::{errors::InvalidMetadataValue, AsciiMetadataValue},
    transport::{Channel, Endpoint},
    Request, Status,
};
use tower::service_fn;
use uuid::Uuid;

use llt_proto::ens::{
    ens_client, login_client, ChallengeRequest, ConnectionError, ConnectionErrorRequest,
};

use crate::{runtime::is_unexpected_task_failure, Authentication, Credentials, EnsError, KeyKind};

const CONTEXT: &str = "ens-auth";
const AUTHENTICATION_KEY: &str = "authentication";
const NORD_VPN_PROTOCOL_KEY: &str = "nord-vpn-protocol";
const DEFAULT_ROOT_CERTIFICATE: &[u8] =
    include_bytes!("../../../data/default_root_certificate.der");
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// ENS errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed VPN uri
    #[error("Failed to parse the vpn server uri: {0}")]
    MalformedVpnUri(#[from] http::Error),
    /// Inner grpc/tonic error
    #[error("ENS transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// GRPC status error
    #[error("GRPC status error: {0}")]
    Status(#[from] tonic::Status),
    /// Exponential backoff creation error
    #[error("Exponential backoff creation failed {0}")]
    ExponentialBackoff(#[from] exponential_backoff::Error),
    #[error("Uuid parsing failed: {0}")]
    UuidParsing(#[from] uuid::Error),
    #[error("Grpc metadata parsing failed: {0}")]
    InvalidMetadata(#[from] InvalidMetadataValue),
    #[error("Invalid key: {reason}")]
    InvalidKey { reason: String },
    #[error("Internal error: {reason}")]
    Internal { reason: String },
}

/// Configuration of the keep alive messages sent over the ENS connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepaliveConfig {
    /// Interval between the keep alive messages, `None` disables the keep alives
    pub interval: Option<Duration>,
    /// How long to wait for a keep alive response before considering the connection dead,
    /// `None` leaves the default of the underlying http client in place
    pub timeout: Option<Duration>,
}

#[derive(Debug)]
pub enum Event {
    Notification {
        connection_error: ConnectionError,
        vpn_uri: String,
    },
    Disconnect(Option<String>),
}

/// `ErrorNotificationService` manages tasks started and stopped to consume the ENS grpc error streams
pub struct ErrorNotificationService {
    quit: Option<(watch::Sender<bool>, JoinHandle<()>)>,
    tx: Sender<Event>,
    socket_pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    // DER encoded root certificate to be use for verification of TLS
    root_certificate: Vec<u8>,
    // Configuration of the keep alive messages sent over the ENS connection
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
}

impl std::fmt::Debug for ErrorNotificationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErrorNotificationService")
            .field("quit", &self.quit)
            .field("tx", &self.tx)
            .field("socket_pool", &"<unknown>")
            .field("allow_only_mlkem", &self.allow_only_mlkem)
            .field("root_certificate", &self.root_certificate)
            .field("keepalive", &self.keepalive)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Drop for ErrorNotificationService {
    fn drop(&mut self) {
        if let Some(join_handle) = self.stop_old_monitor() {
            // Can't wait on the handle in the Drop
            // but we can abort it
            join_handle.abort();
        }
    }
}

impl ErrorNotificationService {
    /// Create new instance with `buffer_size` used for the error notifications channel
    pub fn new(
        buffer_size: NonZeroUsize,
        socket_pool: Arc<SocketPool>,
        allow_only_mlkem: bool,
        root_certificate_override: Option<Vec<u8>>,
        mut keepalive: KeepaliveConfig,
        user_agent: HeaderValue,
    ) -> (Self, Receiver<Event>) {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer_size.get());

        if let Some(cert) = &root_certificate_override {
            info!(
                "Will use root certificate override: {:?}",
                BASE64_STANDARD.encode(cert)
            );
        }

        if keepalive.interval == Some(Duration::ZERO) {
            warn!("Keepalive interval set to 0, resetting to default");
            keepalive.interval = Some(DEFAULT_KEEPALIVE_INTERVAL);
        }
        if keepalive.timeout == Some(Duration::ZERO) {
            warn!("Keepalive timeout set to 0, resetting to default");
            keepalive.timeout = Some(DEFAULT_KEEPALIVE_TIMEOUT);
        }

        (
            Self {
                quit: None,
                tx,
                socket_pool,
                allow_only_mlkem,
                root_certificate: root_certificate_override
                    .unwrap_or_else(|| DEFAULT_ROOT_CERTIFICATE.to_vec()),
                keepalive,
                user_agent,
            },
            rx,
        )
    }

    pub async fn start_monitor_on_port(
        &mut self,
        vpn_ip: IpAddr,
        ens_port: u16,
        authentication: ClientAuthentication,
        backoff: impl Backoff,
    ) {
        info!("Will start ENS monitoring on {vpn_ip}:{ens_port}");
        self.stop().await;

        let (quit_tx, quit_rx): (watch::Sender<bool>, watch::Receiver<bool>) =
            watch::channel(false);

        // Needs to be http and not https, otherwise grpc will add another layer of https
        // on top of our own custom one
        let vpn_uri = format!("http://{vpn_ip}:{ens_port}");

        let pool = self.socket_pool.clone();
        let tx = self.tx.clone();
        let allow_only_mlkem = self.allow_only_mlkem;
        let root_certificate = self.root_certificate.clone();
        let keepalive = self.keepalive;
        let user_agent = self.user_agent.clone();

        let join_handle = tokio::spawn(async move {
            // This future is too big for keeping it on the stack
            if let Err(e) = Box::pin(task(
                &vpn_uri,
                authentication,
                pool.clone(),
                tx,
                quit_rx,
                allow_only_mlkem,
                backoff,
                root_certificate,
                keepalive,
                user_agent,
            ))
            .await
            {
                warn!("ENS task for {vpn_uri} failed: {e}");
            }
        });

        self.quit = Some((quit_tx, join_handle));
    }

    /// Stop ENS
    pub async fn stop(&mut self) {
        if let Some(join_handle) = self.stop_old_monitor() {
            debug!("Will wait for the old ENS task to end");
            join_handle.abort(); // Since the task might be in the grpc connection establishment, it might not be able
                                 // to receive and react to te quit signal. Which is why we need to cancel it here, so
                                 // that we are not stuck for a long time in the await.
            if let Err(e) = join_handle.await {
                if is_unexpected_task_failure(&e) {
                    warn!("Previous ENS task failed to stop: {e}");
                }
            }
        }
    }

    fn stop_old_monitor(&mut self) -> Option<JoinHandle<()>> {
        let (quit_channel, join_handle) = self.quit.take()?;
        debug!("Previous ENS task will be stopped");
        if let Err(e) = quit_channel.send(true) {
            // The only way to lose the receiver is the monitor task ending on
            // its own, so there is nothing left to stop.
            debug!("ENS monitor had already stopped: {e}");
            return None;
        }
        Some(join_handle)
    }
}

pub struct ClientKeys {
    pub local_private_key: SecretKey,
    pub vpn_public_key: PublicKey,
    pub kind: KeyKind,
}

pub enum ClientAuthentication {
    Credentials {
        #[expect(unused)]
        credentials: Credentials,
    },
    Keys {
        keys: ClientKeys,
    },
}

impl TryFrom<Authentication> for ClientAuthentication {
    type Error = EnsError;

    fn try_from(value: Authentication) -> Result<Self, Self::Error> {
        match value {
            Authentication::Credentials { credentials } => Ok(Self::Credentials { credentials }),
            Authentication::Keys { keys } => {
                let vpn_public_key =
                    keys.vpn_public_key
                        .0
                        .clone()
                        .try_into()
                        .map_err(|_e| Error::InvalidKey {
                            // error here is just a Vec<u8> so no point in adding it to the reason below
                            reason: "vpn public key conversion failed".to_owned(),
                        })?;
                let local_private_key: SecretKey =
                    keys.local_private_key.0.clone().try_into().map_err(|_e| {
                        Error::InvalidKey {
                            // error here is just a Vec<u8> so no point in adding it to the reason below
                            reason: "local private key conversion failed".to_owned(),
                        }
                    })?;

                Ok(Self::Keys {
                    keys: ClientKeys {
                        local_private_key,
                        vpn_public_key,
                        kind: keys.kind,
                    },
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn task(
    vpn_uri: &str,
    authentication: ClientAuthentication,
    pool: Arc<SocketPool>,
    tx: Sender<Event>,
    mut quit_rx: watch::Receiver<bool>,
    allow_only_mlkem: bool,
    mut backoff: impl Backoff,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<(), Error> {
    'outer: loop {
        macro_rules! restart {
            ($backoff: expr) => {
                tokio::time::sleep(backoff.get_backoff()).await;
                backoff.next_backoff();
                continue 'outer;
            };
        }
        /// If the Err is returned but ENS shouldn't quit yet, the outer loop will be restarted
        /// and the task will reconnect. If we should quit, the task will terminate. In case of Ok
        /// case, the macro will evaluate to the inner value of Ok.
        macro_rules! handle_error {
            ($value: expr, $backoff: expr) => {
                match $value {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("ENS task transient failure: {e} source: {:?}", e.source());
                        if *quit_rx.borrow() == true {
                            break 'outer;
                        }
                        restart!($backoff);
                    }
                }
            };
        }

        let pool = pool.clone();
        let external_channel = handle_error!(
            Box::pin(create_external_channel(
                vpn_uri,
                pool,
                allow_only_mlkem,
                root_certificate.clone(),
                keepalive,
                user_agent.clone()
            ))
            .await,
            backoff
        );

        let (authenticated_challenge, nord_vpn_protocol) = match &authentication {
            ClientAuthentication::Credentials { .. } => todo!(),
            ClientAuthentication::Keys { keys } => {
                let authenticated_challenge = handle_error!(
                    get_login_challenge(
                        external_channel.clone(),
                        keys.vpn_public_key,
                        keys.local_private_key.clone(),
                    )
                    .await,
                    backoff
                );
                (authenticated_challenge, keys.kind.protocol_name())
            }
        };

        debug!("Got the authentication challenge, will wait for the error notifications");

        let mut client = ens_client::EnsClient::with_interceptor(
            external_channel,
            authentication_interceptor(authenticated_challenge, nord_vpn_protocol),
        );

        let connection = handle_error!(
            client
                .connection_errors(ConnectionErrorRequest::default())
                .await,
            backoff
        );
        let mut connection_error_stream = connection.into_inner();
        loop {
            select! {
                _ = quit_rx.wait_for(|b| *b) => {
                    info!("ENS monitor for '{vpn_uri}' ends");
                    break 'outer;
                }
                connection_error = connection_error_stream.message() => {
                    warn!("Received error notification for '{vpn_uri}': {connection_error:?}");
                    match connection_error {
                        Ok(Some(connection_error)) => {
                            backoff.reset();
                            if let Err(e) = tx.try_send(Event::Notification{connection_error, vpn_uri: vpn_uri.to_owned()}) {
                                warn!("Failed to publish newly received error notification: {e}");
                            }
                        }
                        Ok(None) => {
                            let msg = format!("'{vpn_uri}' closed the grpc stream");
                            debug!("{msg}");
                            if let Err(e) = tx.try_send(Event::Disconnect(Some(msg))) {
                                warn!("Failed to publish disconnect: {e}");
                            }
                            break 'outer;
                        }
                        Err(e) => {
                            // After the first error, the stream will never return any new value, which means
                            // we need to reconnect. For details, see: https://github.com/hyperium/tonic/blob/c9cc210cb7c6f3f937786a3134c682761a26c65c/tonic/src/codec/decode.rs#L392-L394
                            error!("GRPC error: {e}");
                            break;
                        }
                    }
                }
            };
        }
        restart!(&mut backoff);
    }
    debug!("ENS monitor for '{vpn_uri}' terminates");
    Ok(())
}

async fn get_login_challenge(
    external_channel: Channel,
    vpn_public_key: PublicKey,
    local_private_key: SecretKey,
) -> Result<AsciiMetadataValue, Error> {
    let mut login_client = login_client::LoginClient::new(external_channel);

    let challenge_response = login_client
        .get_challenge(ChallengeRequest::default())
        .await?;
    let challenge = &challenge_response.get_ref().challenge;
    let challenge = Uuid::from_str(challenge)?;
    let shared_secret = local_private_key.ecdh(&vpn_public_key);

    let mut authentication = vec![];
    authentication.extend_from_slice(&local_private_key.public());
    authentication.extend_from_slice(&challenge.into_bytes());
    let authentication_tag = authentication_tag(&shared_secret, &authentication);
    authentication.extend_from_slice(&authentication_tag);
    let authentication = BASE64_STANDARD.encode(&authentication);

    Ok(AsciiMetadataValue::try_from(authentication)?)
}

fn authentication_interceptor(
    authentication_value: AsciiMetadataValue,
    nord_vpn_protocol: AsciiMetadataValue,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> {
    move |mut req: Request<()>| {
        req.metadata_mut()
            .insert(AUTHENTICATION_KEY, authentication_value.clone());
        req.metadata_mut()
            .insert(NORD_VPN_PROTOCOL_KEY, nord_vpn_protocol.clone());
        Ok(req)
    }
}

async fn create_external_channel(
    vpn_uri: &str,
    pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<Channel, Error> {
    let socket_factory = move |uri: Uri| {
        let pool = pool.clone();
        let root_certificate = root_certificate.clone();
        async move {
            let Some(host) = uri.host() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "missing host in vpn uri",
                ));
            };
            let Some(port) = uri.port_u16() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "missing port in vpn uri",
                ));
            };

            let socket = pool.new_external_tcp_v4(None)?;
            let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            if let Some(resolved) = lookup_host((host, port)).await?.next() {
                let tcp_stream = socket.connect(resolved).await?;
                let tls_connector = make_tls_connector(allow_only_mlkem, &root_certificate)?;
                let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
                return Ok::<_, std::io::Error>(TokioIo::new(tls_stream));
            }

            Err(std::io::Error::other(format!(
                "None of the IPs resolved from {host} accepted ENS over TLS"
            )))
        }
    };

    let endpoint = Endpoint::try_from(vpn_uri.to_owned())?.user_agent(user_agent)?;

    let endpoint = if let Some(interval) = keepalive.interval {
        endpoint.http2_keep_alive_interval(interval)
    } else {
        endpoint
    };
    let endpoint = if let Some(timeout) = keepalive.timeout {
        endpoint.keep_alive_timeout(timeout)
    } else {
        endpoint
    };

    // Strictly this is not needed in our case since we have a long lived connection
    // that we want to keep alive. This setting helps in the case where there is
    // **no** active rpc connection and we want to make a new rpc call after a while.
    let endpoint = if keepalive.interval.is_some() {
        endpoint.keep_alive_while_idle(true)
    } else {
        endpoint
    };

    Ok(endpoint
        .connect_with_connector(service_fn(socket_factory))
        .await?)
}

fn make_crypto_provider(allow_only_mlkem: bool) -> Arc<CryptoProvider> {
    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();

    if allow_only_mlkem {
        provider.kx_groups =
            vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }

    Arc::new(provider)
}

fn make_trusted_root_cert_verifier(
    crypto_provider: Arc<CryptoProvider>,
    root_certificate: &[u8],
) -> std::io::Result<Arc<impl ServerCertVerifier>> {
    use rustls::{
        client::{danger::HandshakeSignatureValid, WebPkiServerVerifier},
        pki_types::{ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    #[derive(Debug)]
    struct CertFingerprintLogger(Arc<WebPkiServerVerifier>);

    impl ServerCertVerifier for CertFingerprintLogger {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(end_entity).into();
            info!(
                "Remote gRPC server ({server_name:?}) sha256 fingerprint: {}",
                hex::encode(hash)
            );

            let verification = self.0.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );

            info!("Remote gRPC TLS certificate verification result: {verification:?}");

            verification
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_verify_schemes()
        }
    }

    let mut roots = RootCertStore::empty();
    let (added, ignored) =
        roots.add_parsable_certificates([CertificateDer::from_slice(root_certificate)]);
    if ignored > 0 {
        warn!("Added {added} certs to trusted store, ignored: {ignored}");
        return Err(std::io::Error::other(
            "Failed to add root cert to the root certificate store",
        ));
    }
    debug!("Added {added} certs to trusted store, ignored: {ignored}");

    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider)
        .build()
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(CertFingerprintLogger(verifier)))
}

fn make_tls_connector(
    allow_only_mlkem: bool,
    root_certificate: &[u8],
) -> std::io::Result<TlsConnector> {
    let provider = make_crypto_provider(allow_only_mlkem);

    let mut tls_config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(make_trusted_root_cert_verifier(
            provider,
            root_certificate,
        )?)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn authentication_tag(secret: &SharedSecret, message: &[u8]) -> [u8; 32] {
    let key = derive_key(CONTEXT, secret);
    *keyed_hash(&key, message).as_bytes()
}

#[cfg(test)]
pub mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            LazyLock,
        },
        time::{Duration, Instant},
    };

    use assert_matches::assert_matches;
    use llt_proto::ens::ConnectionError;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rstest::rstest;
    use telio_crypto::SecretKey;
    use telio_sockets::NativeProtector;
    use telio_utils::{
        exponential_backoff::{ExponentialBackoff, ExponentialBackoffBounds},
        Hidden,
    };
    use tokio::{
        sync::oneshot,
        time::{error::Elapsed, timeout},
    };

    use tonic::service::Interceptor;

    use crate::{
        test_support::{spawn_server_with_interceptor, Command, GrpcStub, ServerConfig, TlsConfig},
        Keys, STATE,
    };

    use super::*;

    use llt_proto::ens::Error as EnsProtoError;

    static SUBJECT_ALT_NAMES: LazyLock<Vec<String>> =
        LazyLock::new(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    const TEST_USER_AGENT: HeaderValue = HeaderValue::from_static("foo bar baz");

    /// The user agent that `init` installed. Tests going through the public
    /// `connect` API send this one, not `TEST_USER_AGENT`.
    pub fn global_user_agent() -> HeaderValue {
        STATE
            .lock()
            .as_ref()
            .expect("global state not initialized")
            .user_agent
            .clone()
    }

    pub async fn spawn_authenticating_server(expected_user_agent: HeaderValue) -> ServerConfig {
        spawn_server_with_interceptor(|stub| CheckAuthenticationInterceptor {
            stub,
            expected_user_agent,
        })
        .await
    }

    async fn recv_connection_error(rx: &mut Receiver<Event>) -> ConnectionError {
        match rx.recv().await {
            Some(Event::Notification {
                connection_error, ..
            }) => connection_error,
            other => panic!("Instead of connection error, received: {other:?}"),
        }
    }

    #[derive(Clone)]
    struct CheckAuthenticationInterceptor {
        stub: GrpcStub,
        expected_user_agent: HeaderValue,
    }

    impl Interceptor for CheckAuthenticationInterceptor {
        fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
            let expected_user_agent = self.expected_user_agent.to_str().unwrap();
            let received_user_agent = req
                .metadata()
                .get("user-agent")
                .and_then(|s| s.to_str().ok())
                .unwrap();

            // tonic appends its own version to the user-agent sent over wire
            assert!(
                received_user_agent.starts_with(expected_user_agent),
                "expected user-agent: {expected_user_agent:?}, got {received_user_agent:?}"
            );

            match req.metadata().get(AUTHENTICATION_KEY) {
                Some(t) => {
                    let decoded = BASE64_STANDARD.decode(t).unwrap();
                    let (client_public_key, challenge_uuid, received_authentication_code) = (
                        PublicKey::new(decoded[..32].try_into().unwrap()),
                        Uuid::from_slice(&decoded[32..48]).unwrap(),
                        &decoded[48..],
                    );

                    if !self.stub.take_challenge(&challenge_uuid) {
                        return Err(Status::unauthenticated("Unknown auth token"));
                    }

                    let secret = self.stub.shared_secret(&client_public_key);
                    if received_authentication_code != authentication_tag(&secret, &decoded[..48]) {
                        return Err(Status::unauthenticated("Challenge not authenticated"));
                    }
                }
                _ => return Err(Status::unauthenticated("No valid auth token")),
            }

            match req.metadata().get(NORD_VPN_PROTOCOL_KEY) {
                Some(val) => {
                    if val != "nordlynx" {
                        return Err(Status::unavailable(format!(
                            "Incorrect {NORD_VPN_PROTOCOL_KEY} in metadata: {val:?}"
                        )));
                    }
                }
                None => {
                    return Err(Status::unavailable(format!(
                        "Missing {NORD_VPN_PROTOCOL_KEY} in metadata"
                    )))
                }
            }

            Ok(req)
        }
    }

    struct TcpRelay {
        port: u16,

        // After setting to true, all **existing** connections become silent (sockets stay open,
        // but no traffic is forwarded).
        silent: Arc<AtomicBool>,
    }

    impl TcpRelay {
        async fn spawn(server_port: u16) -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let silent = Arc::new(AtomicBool::new(false));

            tokio::spawn({
                let silent = silent.clone();
                async move {
                    while let Ok((client, _)) = listener.accept().await {
                        let connected_before_silent = !silent.load(Ordering::Relaxed);
                        let server = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
                            .await
                            .unwrap();
                        let (mut client_rx, mut client_tx) = client.into_split();
                        let (mut server_rx, mut server_tx) = server.into_split();

                        // server -> client
                        tokio::spawn({
                            let silent = silent.clone();
                            async move {
                                let mut buf = [0u8; 4096];
                                loop {
                                    match server_rx.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            if connected_before_silent
                                                && silent.load(Ordering::Relaxed)
                                            {
                                                continue;
                                            }
                                            if client_tx.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        });

                        // client -> server
                        tokio::spawn({
                            let silent = silent.clone();
                            async move {
                                let mut buf = [0u8; 4096];
                                loop {
                                    match client_rx.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            // Keep draining the client, just never let anything
                                            // through - a silent server still reads its socket.
                                            if connected_before_silent
                                                && silent.load(Ordering::Relaxed)
                                            {
                                                continue;
                                            }
                                            if server_tx.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            });

            Self { port, silent }
        }
    }

    fn client_authentication(
        client_private_key: &SecretKey,
        vpn_public_key: PublicKey,
    ) -> ClientAuthentication {
        Authentication::Keys {
            keys: Keys {
                local_private_key: Hidden(client_private_key.to_vec()),
                vpn_public_key: Hidden(vpn_public_key.to_vec()),
                kind: crate::KeyKind::NordLynx,
            },
        }
        .try_into()
        .unwrap()
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn keepalives_trigger_reconnect_for_connections_that_become_silent(
        #[values(1, 5, 10)] interval: u64,
        #[values(1, 5, 10)] timeout: u64,
    ) {
        let client_private_key = SecretKey::gen();
        let server_config = spawn_authenticating_server(TEST_USER_AGENT).await;
        let relay = TcpRelay::spawn(server_config.port).await;
        let interval = Duration::from_secs(interval);
        let timeout = Duration::from_secs(timeout);

        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_mlkem,
            Some(server_config.tls_config.ca_cert.der().to_vec()),
            KeepaliveConfig {
                interval: Some(interval),
                timeout: Some(timeout),
            },
            TEST_USER_AGENT,
        );

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            relay.port,
            client_authentication(&client_private_key, server_config.public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await;

        server_config
            .send(Command::Send(ConnectionError {
                code: EnsProtoError::Unauthenticated as i32,
                additional_info: Some("before the silence".to_owned()),
            }))
            .await;
        let before_the_silence = recv_connection_error(&mut rx).await;

        let before_timestamp = Instant::now();
        assert_eq!(
            before_the_silence.additional_info.as_deref(),
            Some("before the silence")
        );

        relay.silent.store(true, Ordering::Relaxed);
        info!("server has gone silent, the client should give up on the connection and reconnect");

        // We have no way to know when exactly the tonic/hyper reconnects. Which means
        // we need to keep resending the event until it is delivered to a new connection.
        let safety_margin = Duration::from_secs(5);
        let deadline = interval + timeout + safety_margin;
        let (Event::Notification { connection_error: after_the_silence, .. }, after_timestamp) = tokio::time::timeout(deadline, async {
            loop {
                server_config
                    .send(Command::Send(ConnectionError {
                        code: EnsProtoError::ServerMaintenance as i32,
                        additional_info: Some("after the silence".to_owned()),
                    }))
                    .await;
                if let Ok(notification) =
                    tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
                {
                    break (notification.unwrap(), Instant::now());
                }
            }
        })
        .await
        .expect("nothing was received after the server went silent - the client stayed parked on the dead connection") else { panic!()};

        assert_eq!(
            after_the_silence.additional_info.as_deref(),
            Some("after the silence")
        );

        let reconnect_time = after_timestamp - before_timestamp;
        assert!(reconnect_time >= (interval + timeout));
        assert!(reconnect_time < (interval + timeout + safety_margin));

        ens.stop().await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn ens_will_not_detect_silent_connections_if_keepalive_interval_is_none(
        #[values(None, Some(1), Some(5), Some(10), Some(20))] keepalive_timeout: Option<u64>,
    ) {
        let client_private_key = SecretKey::gen();
        let server_config = spawn_authenticating_server(TEST_USER_AGENT).await;
        let relay = TcpRelay::spawn(server_config.port).await;

        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_mlkem,
            Some(server_config.tls_config.ca_cert.der().to_vec()),
            KeepaliveConfig {
                interval: None,
                timeout: keepalive_timeout.map(Duration::from_secs),
            },
            TEST_USER_AGENT,
        );

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            relay.port,
            client_authentication(&client_private_key, server_config.public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await;

        server_config
            .send(Command::Send(ConnectionError {
                code: EnsProtoError::Unauthenticated as i32,
                additional_info: Some("before the silence".to_owned()),
            }))
            .await;
        let before_the_silence = recv_connection_error(&mut rx).await;

        assert_eq!(
            before_the_silence.additional_info.as_deref(),
            Some("before the silence")
        );

        relay.silent.store(true, Ordering::Relaxed);
        info!("server has gone silent, but without the keepalives the client will not notice");

        let next_notification = timeout(Duration::from_secs(30), async {
            loop {
                server_config
                    .send(Command::Send(ConnectionError {
                        code: EnsProtoError::ServerMaintenance as i32,
                        additional_info: Some("after the silence".to_owned()),
                    }))
                    .await;
                if let Ok(notification) = timeout(Duration::from_millis(500), rx.recv()).await {
                    break (notification.unwrap(), Instant::now());
                }
            }
        })
        .await;

        assert_matches!(next_notification, Err(Elapsed { .. }));

        ens.stop().await;
    }

    async fn collect_errors(n: usize, rx: &mut Receiver<Event>) -> Vec<(ConnectionError, String)> {
        let mut ret = vec![];
        while ret.len() < n {
            let Event::Notification {
                connection_error,
                vpn_uri,
            } = rx.recv().await.unwrap()
            else {
                continue;
            };
            ret.push((connection_error, vpn_uri));
        }
        ret
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens_backoff() {
        let client_private_key = SecretKey::gen();

        let errors_to_emit = [
            ConnectionError {
                code: EnsProtoError::Unknown as i32,
                additional_info: None,
            },
            ConnectionError {
                code: EnsProtoError::ConnectionLimitReached as i32,
                additional_info: Some("additional info".to_owned()),
            },
        ];

        let server_config = spawn_authenticating_server(TEST_USER_AGENT).await;

        let allow_only_mlkem = true;

        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_mlkem,
            Some(server_config.tls_config.ca_cert.der().to_vec()),
            KeepaliveConfig::default(),
            TEST_USER_AGENT,
        );

        let mut backoff = telio_utils::exponential_backoff::MockBackoff::new();

        backoff.expect_reset().times(4).return_const(());
        backoff
            .expect_get_backoff()
            .times(1)
            .return_const(Duration::from_secs(1));
        backoff.expect_next_backoff().times(1).return_const(());

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            server_config.port,
            client_authentication(&client_private_key, server_config.public_key),
            backoff,
        )
        .await;

        for e in errors_to_emit.clone() {
            server_config.send(Command::Send(e)).await;
        }
        server_config
            .send(Command::Error(tonic::Status::unknown("some message")))
            .await;
        server_config.send(Command::End).await;
        for e in errors_to_emit {
            server_config.send(Command::Send(e)).await;
        }
        let _collected_errors = collect_errors(3, &mut rx).await;
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_ens_fails_without_x25519mlkem768_support() {
        let server_private_key = SecretKey::gen();
        let server_public_key = server_private_key.public();
        let client_private_key = SecretKey::gen();

        let (port_tx, port_rx) = oneshot::channel();
        let expected_errors = Arc::new(AtomicUsize::new(0));

        let expected_errors_clone = expected_errors.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let actual_addr = listener.local_addr().unwrap();
            port_tx.send(actual_addr.port()).unwrap();

            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(SUBJECT_ALT_NAMES.clone()).unwrap();

            // Create a TLS server that explicitly does NOT support X25519MLKEM768
            // by using a provider that only supports traditional key exchange algorithms
            let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
            provider.kx_groups = vec![
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
                tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519,
            ];

            let server_config =
                tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                            cert.der().to_vec(),
                        )],
                        tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(
                            signing_key.serialize_der(),
                        )
                        .unwrap(),
                    )
                    .unwrap();

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = tls_acceptor.clone();
                let expected_errors = expected_errors_clone.clone();
                tokio::spawn(async move {
                    let err = acceptor.accept(stream).await.unwrap_err();
                    let rustls_err = err
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<rustls::Error>()
                        .unwrap();
                    assert_eq!(
                        *rustls_err,
                        rustls::Error::PeerIncompatible(
                            rustls::PeerIncompatible::NoKxGroupsInCommon
                        )
                    );
                    // Making sure that we reach this point, tokio::spawn can 'swallow' panics
                    expected_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        });

        let allow_only_mlkem = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_mlkem,
            None,
            KeepaliveConfig::default(),
            TEST_USER_AGENT,
        );

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port_rx.await.unwrap(),
            client_authentication(&client_private_key, server_public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await;

        // Wait a bit for the background task to attempt TLS handshake and fail
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Try to receive from the error channel - this should timeout
        // because the connection should fail during TLS handshake before any errors are sent
        let timeout_result = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;

        // We expect a timeout because the connection should fail during TLS handshake
        // and never reach the point where it can send error notifications
        assert!(timeout_result.is_err());

        ens.stop().await;

        assert_eq!(expected_errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    fn make_socket_pool() -> Arc<SocketPool> {
        Arc::new(SocketPool::new(
            NativeProtector::new(
                #[cfg(target_os = "macos")]
                false,
            )
            .unwrap(),
        ))
    }

    #[test]
    fn test_cert_verification_rejects_invalid_request() {
        use rustls::{
            client::danger::ServerCertVerifier,
            internal::msgs::codec::{Codec, Reader},
            DigitallySignedStruct, SignatureScheme,
        };

        let tls = TlsConfig::new();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der()).unwrap();
        let leaf_cert = tls.leaf_cert.der();

        // DigitallySignedStruct with incorrect signature bytes
        // Wire format: 2 bytes scheme (big-endian u16) + 2 bytes length + signature bytes
        let scheme_u16: u16 = SignatureScheme::ECDSA_NISTP256_SHA256.into();
        let garbage_signature = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        let mut wire_bytes = Vec::new();
        wire_bytes.extend_from_slice(&scheme_u16.to_be_bytes());
        wire_bytes.extend_from_slice(
            &u16::try_from(garbage_signature.len())
                .unwrap()
                .to_be_bytes(),
        );
        wire_bytes.extend_from_slice(&garbage_signature);

        let mut reader = Reader::init(&wire_bytes);
        let dss = DigitallySignedStruct::read(&mut reader).expect("Failed to parse DSS");
        assert_eq!(dss.scheme, SignatureScheme::ECDSA_NISTP256_SHA256);

        let message = b"this is a TLS handshake message that was NOT signed by the cert's key";

        let tls12_result = verifier.verify_tls12_signature(message, leaf_cert, &dss);
        assert_matches!(
            tls12_result,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ))
        );

        let tls13_result = verifier.verify_tls13_signature(message, leaf_cert, &dss);
        assert_matches!(
            tls13_result,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ))
        );
    }

    #[test]
    fn test_cert_verification_accepts_correct_request() {
        use rustls::{
            client::danger::ServerCertVerified,
            pki_types::{ServerName, UnixTime},
        };

        let tls = TlsConfig::new();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der()).unwrap();

        assert_matches!(
            verifier.verify_server_cert(
                tls.leaf_cert.der(),
                &[tls.ca_cert.der().clone()],
                &ServerName::DnsName("localhost".try_into().unwrap()),
                &[],
                UnixTime::now(),
            ),
            Ok(ServerCertVerified { .. })
        );
    }

    #[test]
    fn test_cert_verification_rejects_incorrect_request() {
        use rustls::pki_types::{ServerName, UnixTime};

        let tls = TlsConfig::new();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der()).unwrap();

        assert_matches!(
            verifier.verify_server_cert(
                tls.leaf_cert.der(),
                &[tls.ca_cert.der().clone()],
                &ServerName::DnsName("some-other-name".try_into().unwrap()),
                &[],
                UnixTime::now(),
            ),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext {
                    expected,
                    presented
                }
            ))
            if
                expected == ServerName::DnsName("some-other-name".try_into().unwrap()) &&
                presented == vec![ "DnsName(\"localhost\")", "IpAddress(127.0.0.1)" ]
        );

        let random_leaf_cert =
            rcgen::generate_simple_self_signed(SUBJECT_ALT_NAMES.clone()).unwrap();

        assert_matches!(
            verifier.verify_server_cert(
                random_leaf_cert.cert.der(),
                &[tls.ca_cert.der().clone()],
                &ServerName::DnsName("localhost".try_into().unwrap()),
                &[],
                UnixTime::now(),
            ),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        );
    }
}
