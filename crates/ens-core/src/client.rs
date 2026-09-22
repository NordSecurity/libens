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
    client::{danger::ServerCertVerifier, EchConfig},
    crypto::{aws_lc_rs::hpke::ALL_SUPPORTED_SUITES, hpke::Hpke, CryptoProvider},
    pki_types::{CertificateDer, DnsName, EchConfigListBytes, ServerName},
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
    Code, Request, Status,
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
const MISSING_HOST_MSG: &str = "missing host in vpn uri";
const MISSING_PORT_MSG: &str = "missing port in vpn uri";
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
    #[error("'{vpn_uri}' presented an untrusted certificate: {reason}")]
    UntrustedCertificate { vpn_uri: String, reason: String },
    /// It was possible to connect with random hostname but to retry_configs
    /// have been returned by the server
    #[error("ECH bootstrapping failed")]
    EchBootstrappingFailed(#[from] std::io::Error), // TODO: add details

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
        let allow_only_mlkem = self.allow_only_mlkem;
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

trait ErrorsExt {
    fn is_auth_rejection(&self) -> bool;
    fn is_ech_offer_rejection(&self) -> bool;
    fn is_untrusted_cert(&self) -> bool;
}

impl ErrorsExt for Status {
    fn is_auth_rejection(&self) -> bool {
        matches!(self.code(), Code::Unauthenticated | Code::PermissionDenied)
    }

    fn is_ech_offer_rejection(&self) -> bool {
        false
    }

    fn is_untrusted_cert(&self) -> bool {
        false
    }
}

impl ErrorsExt for Error {
    fn is_auth_rejection(&self) -> bool {
        matches!(self, Error::Status(status) if status.is_auth_rejection())
    }

    fn is_ech_offer_rejection(&self) -> bool {
        matches!(self, Error::EchBootstrappingRejected)
    }

    fn is_untrusted_cert(&self) -> bool {
        matches!(self, Error::UntrustedCertificate { .. })
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

async fn publish_auth_rejection(tx: &Sender<Event>, vpn_uri: &Uri, error: &impl std::fmt::Display) {
    error!("ENS authentication for '{vpn_uri}' was rejected: {error}");

    let reason = format!("'{vpn_uri}' rejected the authentication");
    publish_disconnect(tx, reason).await;
}

async fn publish_ech_offer_rejection(
    tx: &Sender<Event>,
    vpn_uri: &Uri,
    error: &impl std::fmt::Display,
) {
    error!("ECH offer for ENS at '{vpn_uri}' was rejected: {error}");

    let reason = format!("'{vpn_uri}' rejected the ECH offer");
    publish_disconnect(tx, reason).await;
}

async fn publish_untrusted_cert(tx: &Sender<Event>, error: &impl std::fmt::Display) {
    let reason = error.to_string();
    error!("{reason}");
    publish_disconnect(tx, reason).await;
}

async fn publish_disconnect(tx: &Sender<Event>, reason: String) {
    if let Err(e) = tx.send(Event::Disconnect(Some(reason))).await {
        warn!("Failed to publish disconnect: {e}");
    }
}

pub(crate) fn stream_closed_reason(vpn_uri: &Uri) -> String {
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
                        if e.is_auth_rejection() {
                            publish_auth_rejection(&tx, vpn_uri, &e).await;
                            break 'outer;
                        }

                        if e.is_ech_offer_rejection() {
                            publish_ech_offer_rejection(&tx, vpn_uri, &e).await;
                            break 'outer;
                        }

                        if e.is_untrusted_cert() {
                            publish_untrusted_cert(&tx, &e).await;
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
                allow_only_mlkem,
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
                    debug!("{msg}");
                    publish_disconnect(&tx, msg).await;
                    break 'outer;
                }
                Err(e) if e.is_auth_rejection() => {
                    publish_auth_rejection(&tx, vpn_uri, &e).await;
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

async fn open_channel(
    vpn_uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<Channel, Error> {
    let attempt = create_external_channel(
        vpn_uri,
        tls.clone(),
        pool,
        allow_only_mlkem,
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

async fn bootstrap_ech(
    uri: &Uri,
    tls: &TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    root_certificate: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    let Some(host) = uri.host() else {
        return Err(Error::Internal {
            reason: MISSING_HOST_MSG.to_owned(),
        });
    };
    let Some(port) = uri.port_u16() else {
        return Err(Error::Internal {
            reason: MISSING_PORT_MSG.to_owned(),
        });
    };

    let expected_tls_hostname = tls.server_name(host).map_err(|e| Error::Internal {
        reason: e.to_string(),
    })?;
    let socket = pool.new_external_tcp_v4(None)?;
    let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    if let Some(resolved) = lookup_host((host, port)).await?.next() {
        let tcp_stream = socket.connect(resolved).await?;

        let tls_connector = make_tls_connector(
            allow_only_mlkem,
            root_certificate,
            EchMode::BootstrapWithExpectedServerName(expected_tls_hostname),
        )?;

        let tls_stream = tls_connector.connect(domain, tcp_stream).await;
        if let Err(e) = tls_stream {
            fn as_rustls_error(e: &std::io::Error) -> Option<&rustls::Error> {
                e.get_ref()?.downcast_ref::<rustls::Error>()
            }

            match as_rustls_error(&e) {
                // This is a successful ECH bootstrap.
                Some(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(
                        retry_configs,
                    )),
                )) => {
                    use rustls::internal::msgs::codec::Codec;
                    return Ok(Some(retry_configs.get_encoding()));
                }
                // App asked for ECH bootstrapping but the server is not returning
                // fresh retry configs, so it's not possible to complete the bootstrap.
                Some(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(None),
                )) => return Ok(None),
                // Server presented an invalid certificate, which is not a transient
                // connection failure, so we will not automatically retry.
                Some(rustls::Error::InvalidCertificate(_)) => {
                    return Err(Error::UntrustedCertificate {
                        vpn_uri: uri.to_string(),
                        reason: e.to_string(),
                    });
                }
                _ => return Err(e.into()),
            }
        }
    }
    Ok(None)
}

async fn create_external_channel(
    vpn_uri: &Uri,
    tls: TlsOptions,
    pool: Arc<SocketPool>,
    allow_only_mlkem: bool,
    root_certificate: Vec<u8>,
    keepalive: KeepaliveConfig,
    user_agent: HeaderValue,
) -> Result<Channel, Error> {
    let bootstrapped_ech_config_list = match tls.ech {
        EchBootstrap::Enabled => {
            let retry_configs = bootstrap_ech(
                vpn_uri,
                &tls,
                pool.clone(),
                allow_only_mlkem,
                &root_certificate,
            )
            .await?;
            if retry_configs.is_none() {
                return Err(Error::EchBootstrappingRejected);
            }
            info!("ECH bootstrapping success");
            retry_configs
        }
        EchBootstrap::Disabled => None,
    };

    let socket_factory = move |uri: Uri| {
        let tls = tls.clone();
        let pool = pool.clone();
        let root_certificate = root_certificate.clone();
        let bootstrapped_ech_config_list = bootstrapped_ech_config_list.clone();
        async move {
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

            let socket = pool.new_external_tcp_v4(None)?;
            let domain = tls.server_name(host)?;

            if let Some(resolved) = lookup_host((host, port)).await?.next() {
                let tcp_stream = socket.connect(resolved).await?;
                let mode = match bootstrapped_ech_config_list {
                    Some(bootstrapped_ech_config_list) => {
                        EchMode::UseEchConfigList(bootstrapped_ech_config_list)
                    }
                    None => EchMode::None,
                };
                let tls_connector = make_tls_connector(allow_only_mlkem, &root_certificate, mode)?;
                let tls_stream = tls_connector.connect(domain, tcp_stream).await?;
                return Ok::<_, std::io::Error>(TokioIo::new(tls_stream));
            }

            Err(std::io::Error::other(format!(
                "None of the IPs resolved from {host} accepted ENS over TLS"
            )))
        }
    };

    let endpoint = Endpoint::try_from(vpn_uri.to_string())?.user_agent(user_agent)?;

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

            // In case of ECH bootstrap we need to switch the hostname. The
            // RFC compliant behaviour of rustls is to pass in here the random
            // public domain that we sent in the initial TLS connection. The
            // server will return certificate that doesn't include that domain
            // but will include the secret domain that we also know. Which is
            // why we switch, so that verification is done against the secret
            // domain.
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

pub fn random_key_config(public_domain: &str) -> Result<Vec<u8>, TryFromIntError> {
    // take the first entry of supported suites
    let hpke = rustls::crypto::aws_lc_rs::hpke::DH_KEM_P256_HKDF_SHA256_AES_128;

    let mut buf = Vec::new();

    // push number of entries to be filled later
    buf.extend(0u16.to_be_bytes());

    // `ECHConfig[0]`
    buf.extend(0xfe0du16.to_be_bytes()); // version
    buf.extend(0u16.to_be_bytes()); // length to be filled later

    let offset = buf.len();

    // `HpkeKeyConfig`
    buf.extend([0u8]); // config_id
    buf.extend(u16::from(hpke.suite().kem).to_be_bytes()); // kem_id

    let key = if let Ok((pubkey, _)) = hpke.generate_key_pair() {
        pubkey.0
    } else {
        // In practice, this should never be triggered
        const FALLBACK_PUBKEY:&[u8] = b"\x04\x8e\x6a\xeb\x94\xc7\x86\x27\x53\xcc\xce\x22\x70\x5f\xa5\x68\xa9\x3d\x82\x0e\x41\xf7\xb1\x75\xbd\xcd\x77\x40\x4a\xd3\x8b\x11\x70\x71\x61\x95\xd7\x5f\x52\xf9\xaa\xc0\x80\xb4\x6b\x8d\x3a\xb1\x5d\xc4\x3e\xea\xae\xf5\x64\xa6\xf0\xcb\x4e\xe3\xef\xf8\xa0\xef\x60";
        FALLBACK_PUBKEY.to_vec()
    };

    buf.extend(u16::try_from(key.len())?.to_be_bytes()); // public key
    buf.extend(key);

    // `HpkeSymetricCipherSuite`
    buf.extend(4u16.to_be_bytes()); // len + 4

    buf.extend(u16::from(hpke.suite().sym.kdf_id).to_be_bytes()); // kdf_id
    buf.extend(u16::from(hpke.suite().sym.aead_id).to_be_bytes()); // aead_id

    buf.extend([0u8]); // maximum_name_length

    let opaque_name = public_domain.as_bytes();
    let len: u8 = opaque_name.len().min(255).try_into()?;

    buf.extend([len]);
    buf.extend(&opaque_name[..len as usize]); // public_name

    buf.extend(0u16.to_be_bytes()); // extensions

    // fixup `ECHConfig` length

    let len = u16::try_from(buf.len() - offset)?;
    buf[(offset - 2)..][..2].copy_from_slice(&len.to_be_bytes());

    // fixup whole list length
    let len = u16::try_from(buf.len() - 2)?;
    buf[..2].copy_from_slice(&len.to_be_bytes());

    Ok(buf)
}

fn generate_random_ech_config_list() -> Result<EchConfigListBytes<'static>, TryFromIntError> {
    let domain = generate_random_domain();
    let ech_config_list = random_key_config(&domain)?;
    Ok(EchConfigListBytes::from(ech_config_list))
}

fn generate_random_domain() -> String {
    // Most popular English words according to https://en.wikipedia.org/wiki/Most_common_words_in_English
    //
    const NOUNS: &[&str] = &[
        "time",
        "person",
        "year",
        "way",
        "day",
        "thing",
        "man",
        "world",
        "life",
        "hand",
        "part",
        "child",
        "eye",
        "woman",
        "place",
        "work",
        "week",
        "case",
        "point",
        "government",
        "company",
        "number",
        "group",
        "problem",
        "fact",
    ];

    const VERBS: &[&str] = &[
        "be", "have", "do", "say", "get", "make", "go", "know", "take", "see", "come", "think",
        "look", "want", "give", "use", "find", "tell", "ask", "work", "seem", "feel", "try",
        "leave", "call",
    ];

    const ADJECTIVES: &[&str] = &[
        "good",
        "new",
        "first",
        "last",
        "long",
        "great",
        "little",
        "own",
        "other",
        "old",
        "right",
        "big",
        "high",
        "different",
        "small",
        "large",
        "next",
        "early",
        "young",
        "important",
        "few",
        "public",
        "bad",
        "same",
        "able",
    ];

    const CODES: &[&str] = &["io", "org", "com"];

    const SEPARATORS: &[&str] = &["", "-"];

    fn sample<'a>(slice: &[&'a str]) -> &'a str {
        slice[rand::random_range(0..slice.len())]
    }

    let mut domain = String::new();

    let sep = sample(SEPARATORS);

    domain.push_str(sample(VERBS));
    domain.push_str(sep);

    if rand::random_bool(0.5) {
        // use adjective
        domain.push_str(sample(ADJECTIVES));
        domain.push_str(sep);
    }

    domain.push_str(sample(NOUNS));
    domain.push('.');
    domain.push_str(sample(CODES));

    domain
}

enum EchMode {
    None,
    BootstrapWithExpectedServerName(ServerName<'static>),
    UseEchConfigList(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum EchBootstrap {
    Enabled,
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
            .map_err(|e| EnsError::InternalError {
                reason: format!("tls_domain is incorrect: {e:?}"),
            })?;
        Ok(TlsOptions {
            domain: tls_domain,
            ech: config.ech,
        })
    }
    fn server_name(&self, host: &str) -> std::io::Result<ServerName<'static>> {
        if let Some(domain) = &self.domain {
            return Ok(ServerName::DnsName(domain.clone()));
        }

        ServerName::try_from(host.to_owned())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

fn make_tls_connector(
    allow_only_mlkem: bool,
    root_certificate: &[u8],
    ech_mode: EchMode,
) -> std::io::Result<TlsConnector> {
    let provider = make_crypto_provider(allow_only_mlkem);

    let (mode, expected_tls_hostname) = match ech_mode {
        EchMode::None => (None, None),
        EchMode::BootstrapWithExpectedServerName(server_name) => {
            let ech_config: EchConfig =
                EchConfig::new(generate_random_ech_config_list(), ALL_SUPPORTED_SUITES)
                    .map_err(std::io::Error::other)?;
            (
                Some(rustls::client::EchMode::Enable(random_ech_config)),
                Some(server_name),
            )
        }
        EchMode::UseEchConfigList(ech_config_bytes) => {
            let ech_config: EchConfig = EchConfig::new(
                EchConfigListBytes::from(ech_config_bytes),
                ALL_SUPPORTED_SUITES,
            )
            .map_err(std::io::Error::other)?;
            (Some(rustls::client::EchMode::Enable(ech_config)), None)
        }
    };

    let tls_config = ClientConfig::builder_with_provider(provider.clone());
    let tls_config = match mode {
        Some(ech_mode) => tls_config
            .with_ech(ech_mode)
            .map_err(std::io::Error::other)?,
        None => tls_config
            .with_safe_default_protocol_versions()
            .map_err(std::io::Error::other)?,
    };
    let mut tls_config = tls_config
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
            spawn_plain_server, Command, EchMode as StubEchMode, GoEchStub, RelayMode,
            ServerConfig, TcpRelay,
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

    struct EchTestbed {
        upstream: ServerConfig,
        stub: GoEchStub,
        relay: Arc<TcpRelay>,
    }

    async fn spawn_ech_testbed(ech: EchBootstrap, invalid_ech_bytes: bool) -> EchTestbed {
        let upstream = spawn_plain_server().await;
        let stub_ech = match ech {
            EchBootstrap::Enabled => {
                if invalid_ech_bytes {
                    StubEchMode::Invalid
                } else {
                    StubEchMode::On
                }
            }
            EchBootstrap::Disabled => StubEchMode::Off,
        };
        let stub = GoEchStub::spawn(upstream.port, ECH_PUBLIC_NAME, Some(TLS_DOMAIN), stub_ech);
        let relay = Arc::new(TcpRelay::spawn(stub.port()).await);

        EchTestbed {
            upstream,
            stub,
            relay,
        }
    }

    impl EchTestbed {
        async fn start_monitor(
            &self,
            ech: EchBootstrap,
            root_certificate: &[u8],
            backoff: impl Backoff,
        ) -> (ErrorNotificationService, Receiver<Event>) {
            let allow_only_mlkem = true;
            let (mut ens, rx) = ErrorNotificationService::new(
                NonZeroUsize::new(10).unwrap(),
                make_socket_pool(),
                allow_only_mlkem,
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

    async fn recv_disconnect_reason(rx: &mut Receiver<Event>) -> String {
        match rx.recv().await {
            Some(Event::Disconnect(Some(reason))) => reason,
            other => panic!("Instead of disconnect, received: {other:?}"),
        }
    }

    async fn assert_reconnects(
        testbed: &EchTestbed,
        rx: &mut Receiver<Event>,
        calls: &StubBackoffCalls,
    ) {
        let emitted = ConnectionError {
            code: EnsProtoError::Unknown as i32,
            additional_info: None,
        };
        testbed.upstream.send(Command::Send(emitted.clone())).await;

        let received = timeout(EVENT_DEADLINE, recv_connection_error(rx))
            .await
            .unwrap();
        assert_eq!(received, emitted);

        assert_eq!(testbed.upstream.streams(), 1);
        assert_eq!(
            calls.get_backoff_calls.load(Ordering::SeqCst),
            FAILED_HANDSHAKES
        );
        assert_eq!(
            calls.next_backoff_calls.load(Ordering::SeqCst),
            FAILED_HANDSHAKES
        );
        assert_eq!(calls.reset_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[test_log::test]
    async fn invalid_ech_bytes_reconnects() {
        let ech = EchBootstrap::Enabled;
        let invalid_ech_bytes = true;
        let testbed = spawn_ech_testbed(ech, invalid_ech_bytes).await;

        let (backoff, calls) = counting_backoff(|_| {});
        let (_ens, mut rx) = testbed
            .start_monitor(ech, testbed.stub.ca_der(), backoff)
            .await;

        assert_reconnects(&testbed, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_refuses_first_handshakes(
        #[values(EchBootstrap::Enabled, EchBootstrap::Disabled)] ech: EchBootstrap,
    ) {
        let testbed = spawn_ech_testbed(ech, false).await;
        testbed.relay.set_mode(RelayMode::Refuse);

        let (backoff, calls) = counting_backoff(forward_after(&testbed.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = testbed
            .start_monitor(ech, testbed.stub.ca_der(), backoff)
            .await;

        assert_reconnects(&testbed, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn backoff_while_server_cuts_first_handshakes_short(
        #[values(EchBootstrap::Enabled, EchBootstrap::Disabled)] ech: EchBootstrap,
    ) {
        let testbed = spawn_ech_testbed(ech, false).await;
        let closer = spawn_handshake_closer().await;
        testbed.relay.set_mode(RelayMode::Redirect(closer));

        let (backoff, calls) = counting_backoff(forward_after(&testbed.relay, FAILED_HANDSHAKES));
        let (_ens, mut rx) = testbed
            .start_monitor(ech, testbed.stub.ca_der(), backoff)
            .await;

        assert_reconnects(&testbed, &mut rx, &calls).await;
    }

    #[rstest]
    #[tokio::test]
    #[test_log::test]
    async fn untrusted_certificate_ends_the_session(
        #[values(EchBootstrap::Enabled, EchBootstrap::Disabled)] ech: EchBootstrap,
    ) {
        let testbed = spawn_ech_testbed(ech, false).await;
        let unrelated_ca = TlsConfig::new();

        let (backoff, calls) = counting_backoff(|_| ());
        let (_ens, mut rx) = testbed
            .start_monitor(ech, unrelated_ca.ca_cert.der(), backoff)
            .await;

        let reason = timeout(EVENT_DEADLINE, recv_disconnect_reason(&mut rx))
            .await
            .unwrap();
        assert!(reason.contains("untrusted certificate"), "{reason}");
        assert!(reason.contains("UnknownIssuer"), "{reason}");
        assert_eq!(testbed.upstream.streams(), 0);
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
        // TODO: add tests for the handling of optional servername
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
        // TODO: server name handling tests
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
