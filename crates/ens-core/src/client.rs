use std::{
    error::Error as _, net::IpAddr, num::NonZeroUsize, str::FromStr, sync::Arc, time::Duration,
};

use telio_crypto::{PublicKey, SecretKey, SharedSecret};
use telio_sockets::{External, SocketPool};
use telio_utils::exponential_backoff::{self, Backoff};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use blake3::{derive_key, keyed_hash};
use http::{HeaderValue, Uri};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use rustls::{
    client::{danger::ServerCertVerifier, EchConfig},
    crypto::{aws_lc_rs::hpke::ALL_SUPPORTED_SUITES, CryptoProvider},
    pki_types::{CertificateDer, DnsName, ServerName},
    ClientConfig, RootCertStore,
};
use tokio::{
    net::{lookup_host, TcpStream},
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
    Code, Request, Status,
};
use tower::service_fn;
use uuid::Uuid;

use llt_proto::ens::{
    ens_client, login_client, ChallengeRequest, ConnectionError, ConnectionErrorRequest,
};

use crate::{runtime::is_unexpected_task_failure, Authentication, Credentials, EnsError, KeyKind};

mod ech;

const CONTEXT: &str = "ens-auth";
const AUTHENTICATION_KEY: &str = "authentication";
const NORD_VPN_PROTOCOL_KEY: &str = "nord-vpn-protocol";
const DEFAULT_ROOT_CERTIFICATE: &[u8] =
    include_bytes!("../../../data/default_root_certificate.der");
const MISSING_HOST_MSG: &str = "missing host in vpn uri";
const MISSING_PORT_MSG: &str = "missing port in vpn uri";
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_BOOTSTRAP_ECH_TIMEOUT: Duration = Duration::from_secs(30);

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
    #[error("Invalid credentials: {reason}")]
    InvalidCredentials { reason: String },
    #[error("Internal error: {reason}")]
    Internal { reason: String },
    #[error("'{vpn_uri}' presented an untrusted certificate: {reason}")]
    UntrustedCertificate { vpn_uri: String, reason: String },
    /// The bootstrap handshake failed before the server sent `retry_configs`.
    #[error("ECH bootstrapping failed")]
    EchBootstrappingFailed {
        #[source]
        source: std::io::Error,
    },
    #[error("ECH bootstrapping rejected")]
    EchBootstrappingRejected,
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
    allow_only_pq: bool,
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
            .field("allow_only_pq", &self.allow_only_pq)
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
    pub fn try_from_config(
        config: &crate::ConfigState,
        socket_pool: Arc<SocketPool>,
        user_agent: HeaderValue,
    ) -> Result<(Self, Receiver<Event>), EnsError> {
        let buffer_size = config
            .buffer_size
            .try_into()
            .map_err(|e| EnsError::InvalidInput {
                reason: format!("buffer_size has to be non zero: {e}"),
            })?;

        let allow_only_pq = config.allow_only_pq;
        let root_certificate_override = config.root_certificate_override.clone();
        let keepalive = config.keepalive;

        Ok(Self::new(
            buffer_size,
            socket_pool,
            allow_only_pq,
            root_certificate_override,
            keepalive,
            user_agent,
        ))
    }

    fn new(
        buffer_size: NonZeroUsize,
        socket_pool: Arc<SocketPool>,
        allow_only_pq: bool,
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
                allow_only_pq,
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
        tls: TlsOptions,
        authentication: ClientAuthentication,
        backoff: impl Backoff,
    ) -> Result<(), Error> {
        info!("Will start ENS monitoring for {vpn_ip}:{ens_port} ({tls:?})");
        self.stop().await;

        let (quit_tx, quit_rx): (watch::Sender<bool>, watch::Receiver<bool>) =
            watch::channel(false);

        // Needs to be http and not https, otherwise grpc will add another layer of https
        // on top of our own custom one
        let vpn_uri =
            Uri::from_str(&format!("http://{vpn_ip}:{ens_port}")).map_err(http::Error::from)?;

        let pool = self.socket_pool.clone();
        let tx = self.tx.clone();
        let allow_only_pq = self.allow_only_pq;
        let root_certificate = self.root_certificate.clone();
        let keepalive = self.keepalive;
        let user_agent = self.user_agent.clone();

        let join_handle = tokio::spawn(async move {
            // This future is too big for keeping it on the stack
            if let Err(e) = Box::pin(task(
                &vpn_uri,
                tls,
                authentication,
                pool.clone(),
                tx,
                quit_rx,
                allow_only_pq,
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

        Ok(())
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
    Credentials { credentials: Credentials },
    Keys { keys: ClientKeys },
}

impl TryFrom<Authentication> for ClientAuthentication {
    type Error = EnsError;

    fn try_from(value: Authentication) -> Result<Self, Self::Error> {
        match value {
            Authentication::WithCredentials { credentials } => {
                credentials.validate()?;
                Ok(Self::Credentials { credentials })
            }
            Authentication::WithKeys { keys } => {
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

trait IsPersistentError: std::fmt::Display {
    fn is_persistent(&self) -> bool;
}

impl IsPersistentError for Status {
    fn is_persistent(&self) -> bool {
        matches!(self.code(), Code::Unauthenticated | Code::PermissionDenied)
    }
}

impl IsPersistentError for Error {
    fn is_persistent(&self) -> bool {
        matches!(self, Error::Status(status) if status.is_persistent())
            || matches!(self, Error::EchBootstrappingRejected)
            || matches!(self, Error::UntrustedCertificate { .. })
    }
}

fn certificate_rejection(error: &Error) -> Option<&rustls::Error> {
    let Error::Transport(transport) = error else {
        return None;
    };

    let mut source = std::error::Error::source(transport);
    while let Some(current) = source {
        let tls = current.downcast_ref::<rustls::Error>().or_else(|| {
            current
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<rustls::Error>()
        });
        if let Some(tls @ rustls::Error::InvalidCertificate(_)) = tls {
            return Some(tls);
        }

        source = current.source();
    }

    None
}

async fn publish_disconnect(tx: &Sender<Event>, reason: String) {
    if let Err(e) = tx.send(Event::Disconnect(Some(reason))).await {
        warn!("Failed to publish disconnect: {e}");
    }
}

async fn publish_persistent_error(tx: &Sender<Event>, e: impl IsPersistentError) {
    publish_disconnect(tx, format!("persistent error {e}")).await;
}

pub fn stream_closed_reason(vpn_uri: &Uri) -> String {
    format!("'{vpn_uri}' closed the grpc stream")
}

#[allow(clippy::too_many_arguments)]
async fn task(
    vpn_uri: &Uri,
    tls: TlsOptions,
    authentication: ClientAuthentication,
    pool: Arc<SocketPool>,
    tx: Sender<Event>,
    mut quit_rx: watch::Receiver<bool>,
    allow_only_pq: bool,
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
                        if e.is_persistent() {
                            publish_persistent_error(&tx, e).await;
                            break 'outer;
                        }

                        warn!("ENS task transient failure: {e} source: {:?}", e.source());
                        if *quit_rx.borrow() == true {
                            break 'outer;
                        }
                        restart!($backoff);
                    }
                }
            };
        }

        let external_channel = handle_error!(
            Box::pin(open_channel(
                vpn_uri,
                &tls,
                pool.clone(),
                allow_only_pq,
                root_certificate.clone(),
                keepalive,
                user_agent.clone(),
            ))
            .await,
            backoff
        );

        let headers = handle_error!(
            prepare_connection_headers(&authentication, &external_channel).await,
            backoff
        );

        debug!("Subscribing to error notifications for '{vpn_uri}'");

        let mut client = ens_client::EnsClient::with_interceptor(
            external_channel,
            authentication_interceptor(headers),
        );

        let connection = handle_error!(
            client
                .connection_errors(ConnectionErrorRequest::default())
                .await,
            backoff
        );
        let mut connection_error_stream = connection.into_inner();
        loop {
            let connection_error = select! {
                _ = quit_rx.wait_for(|b| *b) => {
                    info!("ENS monitor for '{vpn_uri}' ends");
                    break 'outer;
                }
                connection_error = connection_error_stream.message() => connection_error,
            };

            warn!("Received error notification for '{vpn_uri}': {connection_error:?}");
            match connection_error {
                Ok(Some(connection_error)) => {
                    backoff.reset();
                    if let Err(e) = tx.try_send(Event::Notification {
                        connection_error,
                        vpn_uri: vpn_uri.to_string(),
                    }) {
                        warn!("Failed to publish newly received error notification: {e}");
                    }
                }
                Ok(None) => {
                    let msg = stream_closed_reason(vpn_uri);
                    publish_disconnect(&tx, msg).await;
                    break 'outer;
                }
                Err(e) if e.is_persistent() => {
                    publish_persistent_error(&tx, e).await;
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
        restart!(&mut backoff);
    }
    info!("ENS monitor for '{vpn_uri}' terminates");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn open_channel(
    vpn_uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_pq: bool,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<Channel, Error> {
    let attempt = create_external_channel(
        vpn_uri,
        tls.clone(),
        pool,
        allow_only_pq,
        root_certificate,
        keepalive,
        user_agent,
    )
    .await;

    let Err(err) = attempt else {
        return attempt;
    };

    let Some(rejection) = certificate_rejection(&err) else {
        return Err(err);
    };

    let untrusted = Error::UntrustedCertificate {
        vpn_uri: vpn_uri.to_string(),
        reason: rejection.to_string(),
    };
    error!("opening channel failed with: {untrusted}");

    Err(untrusted)
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
    headers: Vec<(&'static str, AsciiMetadataValue)>,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> {
    move |mut req: Request<()>| {
        for (k, v) in &headers {
            req.metadata_mut().insert(*k, v.clone());
        }
        Ok(req)
    }
}

fn connect_error(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        return Error::Internal {
            reason: e.to_string(),
        };
    }

    Error::EchBootstrappingFailed { source: e }
}

async fn connect_tcp<'a>(
    uri: &'a Uri,
    pool: &SocketPool,
    tls: &TlsOptions,
) -> std::io::Result<(&'a str, ServerName<'static>, External<TcpStream>)> {
    let Some(host) = uri.host() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            MISSING_HOST_MSG,
        ));
    };
    let Some(port) = uri.port_u16() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            MISSING_PORT_MSG,
        ));
    };

    let server_name = tls.server_name(host)?;
    let socket = pool.new_external_tcp_v4(None)?;
    let Some(resolved) = lookup_host((host, port)).await?.next() else {
        return Err(std::io::Error::other(format!(
            "None of the IPs resolved from {host} accepted ENS over TLS"
        )));
    };

    Ok((host, server_name, socket.connect(resolved).await?))
}

async fn create_external_channel(
    vpn_uri: &Uri,
    tls: TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_pq: bool,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<Channel, Error> {
    let bootstrapped_ech_config_list = match tls.ech {
        EchBootstrap::Enabled(timeout) => Some(
            ech::bootstrap(
                vpn_uri,
                &tls,
                pool.clone(),
                allow_only_pq,
                &root_certificate,
                timeout,
            )
            .await?,
        ),
        EchBootstrap::Disabled => None,
    };

    let socket_factory = move |uri: Uri| {
        let tls = tls.clone();
        let pool = pool.clone();
        let root_certificate = root_certificate.clone();
        let bootstrapped_ech_config_list = bootstrapped_ech_config_list.clone();
        async move {
            let (_, domain, tcp_stream) = connect_tcp(&uri, &pool, &tls).await?;
            let mode = match bootstrapped_ech_config_list {
                Some(bootstrapped_ech_config_list) => {
                    EchMode::UseEchConfigList(bootstrapped_ech_config_list, domain.clone())
                }
                None => EchMode::None,
            };
            let tls_connector = make_tls_connector(allow_only_pq, &root_certificate, mode)?;
            let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
            Ok::<_, std::io::Error>(TokioIo::new(tls_stream))
        }
    };

    let endpoint = Endpoint::from(vpn_uri.clone()).user_agent(user_agent)?;

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

fn make_crypto_provider(allow_only_pq: bool) -> Arc<CryptoProvider> {
    let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();

    if allow_only_pq {
        provider.kx_groups =
            vec![tokio_rustls::rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }

    Arc::new(provider)
}

fn make_trusted_root_cert_verifier(
    crypto_provider: Arc<CryptoProvider>,
    root_certificate: &[u8],
    expected_tls_hostname: Option<ServerName<'static>>,
) -> std::io::Result<Arc<impl ServerCertVerifier>> {
    use rustls::{
        client::{danger::HandshakeSignatureValid, WebPkiServerVerifier},
        pki_types::{ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    #[derive(Debug)]
    struct CertFingerprintLogger {
        inner: Arc<WebPkiServerVerifier>,
        expected_tls_hostname: Option<ServerName<'static>>,
    }

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

            // When the server rejects ECH, rustls passes the outer public_name
            // here (the random one during bootstrap, the server's one
            // otherwise). Our servers have no certificate for it, so verify
            // against the real domain. This covers both the initial bootstrap
            // and a case when the crypto keys change on the server between the
            // bootstrap and the actual tls/grpc connection.
            let verification = self.inner.verify_server_cert(
                end_entity,
                intermediates,
                match &self.expected_tls_hostname {
                    Some(expected_tls_hostname) => expected_tls_hostname,
                    None => server_name,
                },
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
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
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

    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider)
        .build()
        .map_err(std::io::Error::other)?;
    Ok(Arc::new(CertFingerprintLogger {
        inner,
        expected_tls_hostname,
    }))
}

enum EchMode {
    None,
    BootstrapWithExpectedServerName(ServerName<'static>),
    UseEchConfigList(EchConfig, ServerName<'static>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum EchBootstrap {
    Enabled(Duration),
    #[default]
    Disabled,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TlsOptions {
    pub(crate) domain: Option<DnsName<'static>>,
    pub(crate) ech: EchBootstrap,
}

impl TlsOptions {
    pub fn new(config: &crate::ConfigState) -> Result<Self, EnsError> {
        let tls_domain: Option<DnsName> = config
            .tls_domain
            .clone()
            .map(TryInto::try_into)
            .transpose()
            .map_err(|e| EnsError::InvalidInput {
                reason: format!("tls_domain is incorrect: {e:?}"),
            })?;
        Ok(TlsOptions {
            domain: tls_domain,
            ech: Self::ech(config),
        })
    }

    fn ech(config: &crate::ConfigState) -> EchBootstrap {
        if !config.enable_ech {
            return EchBootstrap::Disabled;
        }

        if config.bootstrap_ech_timeout == Duration::ZERO {
            warn!("Bootstrap ECH timeout set to 0, resetting to default");
            return EchBootstrap::Enabled(DEFAULT_BOOTSTRAP_ECH_TIMEOUT);
        }

        EchBootstrap::Enabled(config.bootstrap_ech_timeout)
    }

    fn server_name(&self, fallback_host: &str) -> std::io::Result<ServerName<'static>> {
        if let Some(domain) = &self.domain {
            return Ok(ServerName::DnsName(domain.clone()));
        }

        ServerName::try_from(fallback_host.to_owned())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

fn make_tls_connector(
    allow_only_pq: bool,
    root_certificate: &[u8],
    ech_mode: EchMode,
) -> std::io::Result<TlsConnector> {
    let provider = make_crypto_provider(allow_only_pq);

    let builder = ClientConfig::builder_with_provider(provider.clone());
    let (tls_config, expected_tls_hostname) = match ech_mode {
        EchMode::None => (builder.with_safe_default_protocol_versions(), None),
        EchMode::BootstrapWithExpectedServerName(server_name) => {
            let random_ech_config = EchConfig::new(
                ech::generate_random_ech_config_list().map_err(std::io::Error::other)?,
                ALL_SUPPORTED_SUITES,
            )
            .map_err(std::io::Error::other)?;
            (
                builder.with_ech(rustls::client::EchMode::Enable(random_ech_config)),
                Some(server_name),
            )
        }
        EchMode::UseEchConfigList(ech_config, expected_tls_hostname) => (
            builder.with_ech(rustls::client::EchMode::Enable(ech_config)),
            Some(expected_tls_hostname),
        ),
    };

    let mut tls_config = tls_config
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(make_trusted_root_cert_verifier(
            provider,
            root_certificate,
            expected_tls_hostname,
        )?)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn authentication_tag(secret: &SharedSecret, message: &[u8]) -> [u8; 32] {
    let key = derive_key(CONTEXT, secret);
    *keyed_hash(&key, message).as_bytes()
}

async fn prepare_connection_headers(
    authentication: &ClientAuthentication,
    external_channel: &Channel,
) -> Result<Vec<(&'static str, AsciiMetadataValue)>, Error> {
    let res = match &authentication {
        ClientAuthentication::Credentials { credentials } => vec![
            (
                http::header::AUTHORIZATION.as_str(),
                credentials.basic_auth()?,
            ),
            (NORD_VPN_PROTOCOL_KEY, credentials.kind.protocol_name()),
        ],
        ClientAuthentication::Keys { keys } => {
            let authenticated_challenge = get_login_challenge(
                external_channel.clone(),
                keys.vpn_public_key,
                keys.local_private_key.clone(),
            )
            .await?;

            vec![
                (AUTHENTICATION_KEY, authenticated_challenge),
                (NORD_VPN_PROTOCOL_KEY, keys.kind.protocol_name()),
            ]
        }
    };
    Ok(res)
}
#[cfg(test)]
pub mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            atomic::{AtomicUsize, Ordering},
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
        Hidden, HiddenBytes, HiddenString,
    };
    use tokio::{
        sync::oneshot,
        time::{error::Elapsed, timeout},
    };

    use ens_stub::{ExpectedAuth, TlsConfig};

    use crate::{
        test_support::{
            spawn_plain_server, BadRetryLasts, Command, EchMode as StubEchMode, GoEchStub,
            RelayMode, RetryConfig, ServerConfig, TcpRelay,
        },
        CredentialsKind, Keys, STATE,
    };

    use super::*;

    use llt_proto::ens::Error as EnsProtoError;

    static SUBJECT_ALT_NAMES: LazyLock<Vec<String>> =
        LazyLock::new(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

    const TEST_USER_AGENT: HeaderValue = HeaderValue::from_static("foo bar baz");
    const ECH_PUBLIC_NAME: &str = "cover.example.com";
    const TLS_DOMAIN: &str = "secret.example.com";
    const FAILED_HANDSHAKES: usize = 3;
    const BACKOFF: Duration = Duration::from_millis(100);
    const EVENT_DEADLINE: Duration = Duration::from_secs(10);
    const BOOTSTRAP_ECH_TIMEOUT: Duration = Duration::from_secs(1);

    #[derive(Clone)]
    pub enum TestAuthConfig {
        NordLynx {
            local_private_key: HiddenBytes,
        },
        NordWhisper {
            username: HiddenString,
            password: HiddenString,
        },
        OpenVpn {
            username: HiddenString,
            password: HiddenString,
        },
    }

    impl TestAuthConfig {
        pub fn new_nordlynx() -> Self {
            Self::NordLynx {
                local_private_key: Hidden(SecretKey::gen().to_vec()),
            }
        }

        pub fn new_nordwhisper() -> Self {
            const LEN: usize = 10;
            Self::NordWhisper {
                username: Hidden(Self::random_string(LEN)),
                password: Hidden(Self::random_string(LEN)),
            }
        }

        pub fn new_openvpn() -> Self {
            const LEN: usize = 10;
            Self::OpenVpn {
                username: Hidden(Self::random_string(LEN)),
                password: Hidden(Self::random_string(LEN)),
            }
        }

        fn random_string(len: usize) -> String {
            use rand::distr::{Alphanumeric, SampleString};
            Alphanumeric.sample_string(&mut rand::rng(), len)
        }

        pub fn to_expected_auth(&self) -> ExpectedAuth {
            match self {
                TestAuthConfig::NordLynx { local_private_key } => ExpectedAuth::NordLynx {
                    client_public_key: Some(
                        SecretKey::new(local_private_key.as_slice().try_into().unwrap()).public(),
                    ),
                },
                TestAuthConfig::NordWhisper { username, password } => ExpectedAuth::NordWhisper {
                    username: username.0.clone(),
                    password: password.0.clone(),
                },
                TestAuthConfig::OpenVpn { username, password } => ExpectedAuth::OpenVpn {
                    username: username.0.clone(),
                    password: password.0.clone(),
                },
            }
        }

        pub fn to_authentication(&self, vpn_public_key: &[u8]) -> Authentication {
            match self.clone() {
                TestAuthConfig::NordLynx { local_private_key } => Authentication::WithKeys {
                    keys: Keys {
                        local_private_key,
                        vpn_public_key: Hidden(vpn_public_key.to_vec()),
                        kind: KeyKind::NordLynx,
                    },
                },
                TestAuthConfig::NordWhisper { username, password } => {
                    Authentication::WithCredentials {
                        credentials: Credentials {
                            username,
                            password,
                            kind: CredentialsKind::NordWhisper,
                        },
                    }
                }
                TestAuthConfig::OpenVpn { username, password } => Authentication::WithCredentials {
                    credentials: Credentials {
                        username,
                        password,
                        kind: CredentialsKind::OpenVPN,
                    },
                },
            }
        }
    }

    pub fn closed_reason(vpn_port: u16) -> String {
        stream_closed_reason(&Uri::from_str(&format!("http://127.0.0.1:{vpn_port}")).unwrap())
    }

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

    pub async fn spawn_authenticating_server(
        expected_user_agent: HeaderValue,
        auth: TestAuthConfig,
    ) -> ServerConfig {
        ens_stub::spawn_server(auth.to_expected_auth(), Some(expected_user_agent))
            .await
            .unwrap()
    }

    async fn recv_connection_error(rx: &mut Receiver<Event>) -> ConnectionError {
        match rx.recv().await {
            Some(Event::Notification {
                connection_error, ..
            }) => connection_error,
            other => panic!("Instead of connection error, received: {other:?}"),
        }
    }

    fn client_authentication(
        client_private_key: &SecretKey,
        vpn_public_key: PublicKey,
    ) -> ClientAuthentication {
        Authentication::WithKeys {
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
        let server_config = spawn_authenticating_server(
            TEST_USER_AGENT,
            TestAuthConfig::NordLynx {
                local_private_key: Hidden(client_private_key.to_vec()),
            },
        )
        .await;
        let relay = TcpRelay::spawn(server_config.port).await;
        let interval = Duration::from_secs(interval);
        let timeout = Duration::from_secs(timeout);

        let allow_only_pq = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_pq,
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
            TlsOptions::default(),
            client_authentication(&client_private_key, server_config.public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await
        .unwrap();

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

        relay.set_mode(RelayMode::Silent);
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
        let server_config = spawn_authenticating_server(
            TEST_USER_AGENT,
            TestAuthConfig::NordLynx {
                local_private_key: Hidden(client_private_key.to_vec()),
            },
        )
        .await;
        let relay = TcpRelay::spawn(server_config.port).await;

        let allow_only_pq = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_pq,
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
            TlsOptions::default(),
            client_authentication(&client_private_key, server_config.public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await
        .unwrap();

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

        relay.set_mode(RelayMode::Silent);
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

        let server_config = spawn_authenticating_server(
            TEST_USER_AGENT,
            TestAuthConfig::NordLynx {
                local_private_key: Hidden(client_private_key.to_vec()),
            },
        )
        .await;

        let allow_only_pq = true;

        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_pq,
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
            TlsOptions::default(),
            client_authentication(&client_private_key, server_config.public_key),
            backoff,
        )
        .await
        .unwrap();

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

    struct EchTestEnv {
        upstream: ServerConfig,
        stub: GoEchStub,
        relay: Arc<TcpRelay>,
    }

    fn stub_ech(ech: EchBootstrap) -> StubEchMode {
        match ech {
            EchBootstrap::Enabled(_) => StubEchMode::On,
            EchBootstrap::Disabled => StubEchMode::Off,
        }
    }

    impl EchTestEnv {
        async fn spawn(stub_ech: StubEchMode) -> Self {
            let upstream = spawn_plain_server().await;
            let stub = GoEchStub::spawn(upstream.port, ECH_PUBLIC_NAME, Some(TLS_DOMAIN), stub_ech);
            let relay = Arc::new(TcpRelay::spawn(stub.port()).await);

            Self {
                upstream,
                stub,
                relay,
            }
        }

        async fn start_monitor(
            &self,
            ech: EchBootstrap,
            root_certificate: &[u8],
            backoff: impl Backoff,
        ) -> (ErrorNotificationService, Receiver<Event>) {
            let allow_only_pq = true;
            let (mut ens, rx) = ErrorNotificationService::new(
                NonZeroUsize::new(10).unwrap(),
                make_socket_pool(),
                allow_only_pq,
                Some(root_certificate.to_vec()),
                KeepaliveConfig::default(),
                TEST_USER_AGENT,
            );

            let tls = TlsOptions {
                domain: Some(TLS_DOMAIN.try_into().unwrap()),
                ech,
            };
            ens.start_monitor_on_port(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                self.relay.port,
                tls,
                client_authentication(&SecretKey::gen(), self.upstream.public_key),
                backoff,
            )
            .await
            .unwrap();

            (ens, rx)
        }
    }

    #[derive(Debug, Default)]
    struct StubBackoffCalls {
        get_backoff: AtomicUsize,
        next_backoff: AtomicUsize,
        reset: AtomicUsize,
    }

    // Preconfigure backoff mock to track the call counts of all fns
    fn counting_backoff(
        on_wait: impl Fn(usize) + Send + 'static,
    ) -> (
        telio_utils::exponential_backoff::MockBackoff,
        Arc<StubBackoffCalls>,
    ) {
        let calls = Arc::new(StubBackoffCalls::default());
        let mut backoff = telio_utils::exponential_backoff::MockBackoff::new();

        let counted = calls.clone();
        backoff.expect_get_backoff().returning(move || {
            on_wait(counted.get_backoff.fetch_add(1, Ordering::SeqCst) + 1);
            BACKOFF
        });

        let counted = calls.clone();
        backoff.expect_next_backoff().returning(move || {
            counted.next_backoff.fetch_add(1, Ordering::SeqCst);
        });

        let counted = calls.clone();
        backoff.expect_reset().returning(move || {
            counted.reset.fetch_add(1, Ordering::SeqCst);
        });

        (backoff, calls)
    }

    fn forward_after(relay: &Arc<TcpRelay>, failed_handshakes: usize) -> impl Fn(usize) + Send {
        let relay = relay.clone();
        move |wait| {
            if wait == failed_handshakes {
                relay.set_mode(RelayMode::Forward);
            }
        }
    }

    async fn spawn_handshake_closer() -> u16 {
        use tokio::io::AsyncReadExt as _;

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut first_byte = [0u8];
                let _ = socket.read(&mut first_byte).await;
            }
        });

        port
    }

    #[derive(Clone, Copy, Debug)]
    enum Junk {
        CaptivePortal,
        UnknownVersion,
        EmptyRecord,
        OversizedRecord,
        TruncatedServerHello,
    }

    impl Junk {
        fn bytes(self) -> &'static [u8] {
            match self {
                Junk::CaptivePortal => {
                    b"HTTP/1.1 302 Found\r\nLocation: http://portal.example/\r\n\r\n"
                }
                Junk::UnknownVersion => b"\x16\x00\x00\x00\x05hello",
                Junk::EmptyRecord => b"\x16\x03\x03\x00\x00",
                Junk::OversizedRecord => b"\x16\x03\x03\xff\xff",
                Junk::TruncatedServerHello => b"\x16\x03\x03\x00\x06\x02\x00\x00\x02\x03\x03",
            }
        }
    }

    async fn spawn_junk_replier(junk: Junk) -> u16 {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut first_byte = [0u8];
                let _ = socket.read(&mut first_byte).await;
                let _ = socket.write_all(junk.bytes()).await;
            }
        });

        port
    }

    async fn spawn_silent_server() -> u16 {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut accepted = vec![];
            while let Ok((socket, _)) = listener.accept().await {
                accepted.push(socket);
            }
        });

        port
    }

    async fn recv_disconnect_reason(rx: &mut Receiver<Event>) -> String {
        match rx.recv().await {
            Some(Event::Disconnect(Some(reason))) => reason,
            other => panic!("Instead of disconnect, received: {other:?}"),
        }
    }

    async fn assert_reconnects(
        env: &EchTestEnv,
        rx: &mut Receiver<Event>,
        calls: &StubBackoffCalls,
    ) {
        let emitted = ConnectionError {
            code: EnsProtoError::Unknown as i32,
            additional_info: None,
        };
        env.upstream.send(Command::Send(emitted.clone())).await;

        let received = timeout(EVENT_DEADLINE, recv_connection_error(rx))
            .await
            .unwrap();
        assert_eq!(received, emitted);

        assert_eq!(env.upstream.streams(), 1);
        assert_eq!(calls.get_backoff.load(Ordering::SeqCst), FAILED_HANDSHAKES);
        assert_eq!(calls.next_backoff.load(Ordering::SeqCst), FAILED_HANDSHAKES);
        assert_eq!(calls.reset.load(Ordering::SeqCst), 1);
    }

    #[rstest]
    #[case(RetryConfig::Malformed)]
    #[case(RetryConfig::BadPublicName)]
    #[case(RetryConfig::TruncatedKem)]
    #[case(RetryConfig::TruncatedKey)]
    #[tokio::test]
    #[test_log::test]
    async fn malformed_server_ech_key_reconnects(#[case] kind: RetryConfig) {
        let ech = EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT);
        let env = EchTestEnv::spawn(StubEchMode::BadRetry {
            kind,
            lasts: BadRetryLasts::Connections(FAILED_HANDSHAKES),
        })
        .await;

        let (backoff, calls) = counting_backoff(|_| {});
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        assert_reconnects(&env, &mut rx, &calls).await;
    }

    #[tokio::test]
    #[test_log::test]
    async fn rotated_server_ech_key_rebootstraps() {
        let ech = EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT);
        let env = EchTestEnv::spawn(StubEchMode::BadRetry {
            kind: RetryConfig::Stale,
            lasts: BadRetryLasts::Connections(1),
        })
        .await;

        let (backoff, calls) = counting_backoff(|_| {});
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        let emitted = ConnectionError {
            code: EnsProtoError::Unknown as i32,
            additional_info: None,
        };
        env.upstream.send(Command::Send(emitted.clone())).await;

        let received = timeout(EVENT_DEADLINE, recv_connection_error(&mut rx))
            .await
            .unwrap();
        assert_eq!(received, emitted);
        assert_eq!(env.upstream.streams(), 1);
        assert_eq!(calls.get_backoff.load(Ordering::SeqCst), 1);
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_refuses_first_handshakes(
        #[values(EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT), EchBootstrap::Disabled)]
        ech: EchBootstrap,
    ) {
        let env = EchTestEnv::spawn(stub_ech(ech)).await;
        env.relay.set_mode(RelayMode::Refuse);

        let (backoff, calls) = counting_backoff(forward_after(&env.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        assert_reconnects(&env, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_cuts_first_handshakes_short(
        #[values(EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT), EchBootstrap::Disabled)]
        ech: EchBootstrap,
    ) {
        let env = EchTestEnv::spawn(stub_ech(ech)).await;
        let closer = spawn_handshake_closer().await;
        env.relay.set_mode(RelayMode::Redirect(closer));

        let (backoff, calls) = counting_backoff(forward_after(&env.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        assert_reconnects(&env, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_replies_with_junk(
        #[values(EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT), EchBootstrap::Disabled)]
        ech: EchBootstrap,
        #[values(
            Junk::CaptivePortal,
            Junk::UnknownVersion,
            Junk::EmptyRecord,
            Junk::OversizedRecord,
            Junk::TruncatedServerHello
        )]
        junk: Junk,
    ) {
        let env = EchTestEnv::spawn(stub_ech(ech)).await;
        let junk = spawn_junk_replier(junk).await;
        env.relay.set_mode(RelayMode::Redirect(junk));

        let (backoff, calls) = counting_backoff(forward_after(&env.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        assert_reconnects(&env, &mut rx, &calls).await;
    }

    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_goes_silent_during_ech_bootstrap() {
        let ech = EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT);
        let env = EchTestEnv::spawn(stub_ech(ech)).await;
        let silent = spawn_silent_server().await;
        env.relay.set_mode(RelayMode::Redirect(silent));

        let (backoff, calls) = counting_backoff(forward_after(&env.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = env.start_monitor(ech, env.stub.ca_der(), backoff).await;

        assert_reconnects(&env, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn untrusted_certificate_ends_the_session(
        #[values(EchBootstrap::Enabled(BOOTSTRAP_ECH_TIMEOUT), EchBootstrap::Disabled)]
        ech: EchBootstrap,
    ) {
        let env = EchTestEnv::spawn(stub_ech(ech)).await;
        let unrelated_ca = TlsConfig::new().unwrap();

        let (backoff, calls) = counting_backoff(|_| ());
        let (_ens, mut rx) = env
            .start_monitor(ech, unrelated_ca.ca_cert.der(), backoff)
            .await;

        let reason = timeout(EVENT_DEADLINE, recv_disconnect_reason(&mut rx))
            .await
            .unwrap();
        assert!(reason.contains("untrusted certificate"), "{reason}");
        assert!(reason.contains("UnknownIssuer"), "{reason}");
        assert_eq!(env.upstream.streams(), 0);
        assert_eq!(calls.get_backoff.load(Ordering::SeqCst), 0);
    }

    async fn spawn_blocked_handshake() -> (u16, oneshot::Receiver<tokio::net::TcpStream>) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = accepted_tx.send(socket);
        });

        (port, accepted_rx)
    }

    #[tokio::test]
    #[test_log::test]
    async fn stop_during_ech_bootstrap_closes_the_connection() {
        use tokio::{io::AsyncReadExt as _, sync::mpsc::error::TryRecvError};

        const TLS_HANDSHAKE_RECORD: u8 = 0x16;

        let (port, accepted) = spawn_blocked_handshake().await;

        let allow_only_pq = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_pq,
            Some(TlsConfig::new().unwrap().ca_cert.der().to_vec()),
            KeepaliveConfig::default(),
            TEST_USER_AGENT,
        );

        let (backoff, calls) = counting_backoff(|_| ());
        let tls = TlsOptions {
            domain: Some(TLS_DOMAIN.try_into().unwrap()),
            ech: EchBootstrap::Enabled(DEFAULT_BOOTSTRAP_ECH_TIMEOUT),
        };
        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            tls,
            client_authentication(&SecretKey::gen(), SecretKey::gen().public()),
            backoff,
        )
        .await
        .unwrap();

        let mut socket = timeout(EVENT_DEADLINE, accepted).await.unwrap().unwrap();
        let mut record_type = [0u8];
        socket.read_exact(&mut record_type).await.unwrap();
        assert_eq!(record_type[0], TLS_HANDSHAKE_RECORD);

        timeout(EVENT_DEADLINE, ens.stop()).await.unwrap();

        let mut rest = vec![];
        let _ = timeout(EVENT_DEADLINE, socket.read_to_end(&mut rest))
            .await
            .unwrap();

        assert_matches!(rx.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(calls.get_backoff.load(Ordering::SeqCst), 0);
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

        let allow_only_pq = true;
        let (mut ens, mut rx) = ErrorNotificationService::new(
            NonZeroUsize::new(10).unwrap(),
            make_socket_pool(),
            allow_only_pq,
            None,
            KeepaliveConfig::default(),
            TEST_USER_AGENT,
        );

        ens.start_monitor_on_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port_rx.await.unwrap(),
            TlsOptions::default(),
            client_authentication(&client_private_key, server_public_key),
            ExponentialBackoff::new(ExponentialBackoffBounds::default()).unwrap(),
        )
        .await
        .unwrap();

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
    fn test_built_in_root_certificate_loads() {
        assert!(make_trusted_root_cert_verifier(
            make_crypto_provider(true),
            DEFAULT_ROOT_CERTIFICATE,
            None,
        )
        .is_ok());
    }

    #[test]
    fn test_cert_verification_rejects_invalid_request() {
        use rustls::{
            client::danger::ServerCertVerifier,
            internal::msgs::codec::{Codec, Reader},
            DigitallySignedStruct, SignatureScheme,
        };

        let tls = TlsConfig::new().unwrap();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der(), None)
                .unwrap();
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

        let tls = TlsConfig::new().unwrap();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der(), None)
                .unwrap();

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

        let tls = TlsConfig::new().unwrap();
        let verifier =
            make_trusted_root_cert_verifier(make_crypto_provider(true), tls.ca_cert.der(), None)
                .unwrap();

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
