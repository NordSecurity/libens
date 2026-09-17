mod api;

use base64::prelude::*;
use std::{
    convert::Infallible,
    error::Error,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Notify, time::timeout};

use chrono::Utc;
use clap::Parser;
use ens::{
    Authentication, Config, ErrorNotificationCallback, Hidden, LogCallback, LogLevel, connect,
    runtime::get_runtime,
};
use log::{debug, info};
use rustls::{
    ClientConfig, RootCertStore,
    client::{EchConfig, EchMode, EchStatus},
    crypto::aws_lc_rs::{default_provider, hpke::ALL_SUPPORTED_SUITES},
    pki_types::{CertificateDer, EchConfigListBytes, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::api::{ApiClient, Server, Technology};

const EXIT_ECH_BOOTSTRAP_FAILED: i32 = 1;
const DEFAULT_ROOT_CERTIFICATE: &[u8] = include_bytes!("../../data/default_root_certificate.der");
const H2_ALPN: &[u8] = b"h2";

#[derive(Debug, Parser)]
struct Args {
    #[clap(long, short, default_value_t = LogLevel::Debug)]
    log_level: LogLevel,

    #[clap(subcommand)]
    commands: Command,
}

#[derive(Parser, Debug)]
enum Command {
    Connect {
        vpn: SocketAddr,

        #[clap(short, long, value_enum)]
        kind: VpnKind,

        #[clap(short, long, env = "NORD_TOKEN")]
        token: String,

        /// Duration of the connection
        #[clap(short, long, default_value_t = 15)]
        duration: u64,

        /// Domain the server certificate is verified against. Sent as SNI, inner SNI with --ech
        #[clap(long)]
        tls_domain: Option<String>,

        /// Bootstrap ECH from the server's retry configs
        #[clap(long)]
        ech: bool,
    },
    /// Run only the ECH bootstrap. Exits with non zero code on failure
    EchBootstrap {
        vpn: SocketAddr,

        /// Domain the server certificate is verified against. Sent as inner SNI
        #[clap(long)]
        tls_domain: String,
    },
    List {
        filter: Option<Filter>,
    },
    Show {
        kind: SelectKind,
        value: String,
    },
}

#[derive(Clone, Debug, Default, clap::ValueEnum)]
enum SelectKind {
    Id,
    #[default]
    Ip,
    Hostname,
}

#[derive(Clone, Debug)]
enum Filter {
    ById(i64),
    ByHostname(String),
    ByKnownTechnology(KnownTechnology),
    ByIp(String),
}

impl Filter {
    fn is_matching(&self, s: &Server) -> bool {
        match self {
            Filter::ById(id) => id == &s.id,
            Filter::ByHostname(h) => h == &s.hostname,
            Filter::ByKnownTechnology(known_technology) => {
                s.technologies.iter().any(|t| known_technology == &t.id)
            }
            Filter::ByIp(ip_addr) => s.ips.iter().any(|ip| &ip.ip.ip == ip_addr),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum KnownTechnology {
    OpenVpnUdp,
    OpenVpnTcp,
    OpenVpnUdpObfuscated,
    OpenVpnTcpObfuscated,
    WireGuard,
    NordWhisper,
}

impl PartialEq<Technology> for KnownTechnology {
    fn eq(&self, other: &Technology) -> bool {
        match (self, other) {
            (KnownTechnology::OpenVpnUdp, Technology::OpenVpnUdp) => true,
            (KnownTechnology::OpenVpnTcp, Technology::OpenVpnTcp) => true,
            (KnownTechnology::OpenVpnUdpObfuscated, Technology::OpenVpnUdpObfuscated) => true,
            (KnownTechnology::OpenVpnTcpObfuscated, Technology::OpenVpnTcpObfuscated) => true,
            (KnownTechnology::WireGuard, Technology::WireGuard) => true,
            (KnownTechnology::NordWhisper, Technology::NordWhisper) => true,
            _ => false,
        }
    }
}

impl FromStr for KnownTechnology {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_lowercase();
        let all = [
            KnownTechnology::OpenVpnUdp,
            KnownTechnology::OpenVpnTcp,
            KnownTechnology::OpenVpnUdpObfuscated,
            KnownTechnology::OpenVpnTcpObfuscated,
            KnownTechnology::WireGuard,
            KnownTechnology::NordWhisper,
        ];
        let matching = all.iter().find(|kt| {
            let name = format!("{kt:?}").to_ascii_lowercase();
            name == s
        });

        if let Some(kt) = matching {
            return Ok(*kt);
        }
        Err(s.to_owned())
    }
}

impl FromStr for Filter {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id: Result<i64, _> = s.parse();
        if let Ok(id) = id {
            return Ok(Filter::ById(id));
        }
        let ip: Result<IpAddr, _> = s.parse();
        if let Ok(_) = ip {
            return Ok(Filter::ByIp(s.to_owned()));
        }
        let tech: Result<KnownTechnology, _> = s.parse();
        if let Ok(tech) = tech {
            return Ok(Filter::ByKnownTechnology(tech));
        }
        Ok(Self::ByHostname(s.to_owned()))
    }
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum VpnKind {
    NordLynx,
    NordWhisper,
    OpenVPN,
}

struct StderrLogCallback;

impl LogCallback for StderrLogCallback {
    fn log(&self, log_level: LogLevel, message: String) {
        let date = Utc::now();
        let level = format!("{log_level:?}").to_ascii_uppercase();
        eprintln!("{date:?} {level} {message}");
    }
}

struct NotificationLoggingCallback(Arc<Notify>);

impl ErrorNotificationCallback for NotificationLoggingCallback {
    fn notify(&self, notification: ens::ConnectionErrorNotification) {
        info!("Notification: {notification:?}");
    }

    fn disconnected(&self, reason: Option<String>) {
        info!("Disconnected: {reason:?}");
        self.0.notify_one();
    }
}

fn main() {
    let args = Args::parse();

    let log_callback = Box::new(StderrLogCallback);
    ens::set_log_callback(args.log_level, log_callback).unwrap();
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let app_version = format!("{name}/v{version}");
    ens::init(app_version.clone()).unwrap();
    info!("version: {}", ens::get_version());
    info!("memory usage: {}", ens::get_memory_usage());

    let api_client = ApiClient::new(&app_version).unwrap();

    match args.commands {
        Command::Connect {
            vpn,
            kind,
            token,
            duration,
            tls_domain,
            ech,
        } => {
            let service_credentials = ens::runtime::get_runtime()
                .unwrap()
                .block_on(api_client.get_service_credentials(&token))
                .unwrap();

            let ip = vpn.ip();

            let local_private_key = BASE64_STANDARD
                .decode(service_credentials.nordlynx_private_key)
                .unwrap();

            let auth = match kind {
                VpnKind::OpenVPN => todo!(),
                VpnKind::NordWhisper => todo!(),
                VpnKind::NordLynx => {
                    let Some(server) = get_runtime()
                        .unwrap()
                        .block_on(api_client.get_server_by_ip(&ip.to_string()))
                        .unwrap()
                    else {
                        eprintln!("Server not found");
                        return;
                    };

                    let Some(public_key) = extract_server_public_key(&server) else {
                        eprintln!("Server has no public key");
                        return;
                    };
                    let vpn_public_key = BASE64_STANDARD.decode(public_key).unwrap();

                    let auth = Authentication::WithKeys {
                        keys: ens::Keys {
                            local_private_key: Hidden(local_private_key),
                            vpn_public_key: Hidden(vpn_public_key),
                            kind: ens::KeyKind::NordLynx,
                        },
                    };
                    auth
                }
            };

            let disconnected = Arc::new(Notify::new());
            let callback = Box::new(NotificationLoggingCallback(disconnected.clone()));

            drop(api_client);
            debug!("api client destroyed");

            let config = Config::new();
            config.set_tls_domain(tls_domain);
            config.set_enable_ech_bootstrap(ech);

            let connection = connect(vpn, None, auth, callback, Arc::new(config)).unwrap();

            get_runtime().unwrap().block_on(async {
                let _ = timeout(Duration::from_secs(duration), disconnected.notified()).await;
            });

            let _ = connection.shutdown().unwrap();
        }
        Command::EchBootstrap { vpn, tls_domain } => {
            let result = check_ech(vpn, tls_domain);
            ens::deinit().unwrap();

            let Err(e) = result else {
                info!("ECH bootstrap succeeded");
                return;
            };

            eprintln!("ECH bootstrap failed: {e}");
            std::process::exit(EXIT_ECH_BOOTSTRAP_FAILED);
        }
        Command::List { filter } => {
            let all_servers = get_runtime()
                .unwrap()
                .block_on(api_client.list_all_servers())
                .unwrap();
            let mut all_servers: Vec<_> = all_servers
                .into_iter()
                .filter(|s| match &filter {
                    Some(f) => f.is_matching(s),
                    None => true,
                })
                .collect();
            all_servers.sort_unstable_by_key(|s| s.name.to_owned());

            if let Some(f) = &filter {
                println!("Using filter: {f:?}");
            }
            println!("ID\tNAME\tHOSTNAME\tIPS\tTECHS");

            for server in all_servers {
                let id = server.id;
                let name = server.name;
                let hostname = server.hostname;

                let mut techs: Vec<_> = server.technologies.iter().map(|t| t.id).collect();
                techs.sort_unstable();
                let techs: Vec<_> = techs.iter().map(ToString::to_string).collect();
                let techs = techs.join(", ");

                let ips: Vec<_> = server.ips.iter().map(|r| r.ip.ip.clone()).collect();
                let ips = ips.join(", ");

                println!("{id} {name} {hostname} {ips} - {techs}");
            }
        }
        Command::Show { kind, value } => {
            let server = match kind {
                SelectKind::Id => {
                    let id = value.parse().unwrap();
                    get_runtime()
                        .unwrap()
                        .block_on(api_client.get_server_by_id(id))
                }
                SelectKind::Ip => get_runtime()
                    .unwrap()
                    .block_on(api_client.get_server_by_ip(&value)),
                SelectKind::Hostname => get_runtime()
                    .unwrap()
                    .block_on(api_client.get_server_by_hostname(&value)),
            }
            .unwrap();

            if let Some(s) = server {
                println!("{s:#?}");
            } else {
                eprintln!("Server not found");
            }
        }
    }

    ens::deinit().unwrap();
}

fn check_ech(vpn: SocketAddr, tls_domain: String) -> Result<(), Box<dyn Error>> {
    let config = Config::new();
    config.set_tls_domain(Some(tls_domain.clone()));

    let Some(retry_configs) = ens::bootstrap_ech(vpn, &Arc::new(config))? else {
        return Err("server returned no retry configs".into());
    };

    let status = get_runtime()?.block_on(ech_handshake(vpn, tls_domain, retry_configs))?;
    info!("ECH status: {status:?}");
    if status != EchStatus::Accepted {
        return Err(format!("ECH not accepted: {status:?}").into());
    }

    Ok(())
}

async fn ech_handshake(
    vpn: SocketAddr,
    tls_domain: String,
    retry_configs: Vec<u8>,
) -> Result<EchStatus, Box<dyn Error>> {
    let ech_config = EchConfig::new(
        EchConfigListBytes::from(retry_configs),
        ALL_SUPPORTED_SUITES,
    )?;

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_slice(DEFAULT_ROOT_CERTIFICATE))?;

    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_ech(EchMode::Enable(ech_config))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![H2_ALPN.to_vec()];

    let tcp_stream = TcpStream::connect(vpn).await?;
    let domain = ServerName::try_from(tls_domain)?;
    let tls_stream = TlsConnector::from(Arc::new(config))
        .connect(domain, tcp_stream)
        .await?;

    Ok(tls_stream.get_ref().1.ech_status())
}

fn extract_server_public_key(s: &Server) -> Option<String> {
    let metadata = s
        .technologies
        .iter()
        .find(|t| t.id == Technology::WireGuard)
        .map(|t| &t.metadata)?;

    metadata
        .iter()
        .find(|m| m.name == Some("public_key".to_owned()))
        .and_then(|m| m.value.clone())
        .and_then(|v| v.as_str().map(|s| s.to_owned()))
}
