use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    process::{Child, ChildStderr, ChildStdout, Command as ProcessCommand, Stdio},
    str::SplitWhitespace,
    sync::{
        mpsc::{self, Sender},
        Arc,
    },
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use ens_core::Config;
use ens_stub::{ExpectedAuth, TlsServerType};
use parking_lot::Mutex;

use super::{ServerConfig, MAX_WAIT_TIME, POLL_INTERVAL};

const ECH_STUB_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/echstub");
const ECH_STUB_START_TIMEOUT: Duration = Duration::from_secs(120);
const ECH_STUB_READY: &str = "ready";
const ECH_STUB_HANDSHAKE: &str = "handshake";
const ECH_STUB_NONE: &str = "-";
const ECH_STUB_BAD_FOREVER: usize = 0;
const ECH_STUB_KEYLOG_ENV: &str = "ECH_STUB_KEYLOG";
const ECH_STUB_LOG_TARGET: &str = "echstub";

pub async fn spawn_plain_server() -> ServerConfig {
    ens_stub::spawn_server_of_type(ExpectedAuth::any_nordlynx(), None, TlsServerType::Plain)
        .await
        .unwrap()
}

/// Retry config the stub serves instead of the good one
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryConfig {
    UnusableAead,
    PqKem,
    UnknownVersion,
    BadPublicName,
    Malformed,
    Stale,
    TruncatedKem,
    TruncatedKey,
}

impl RetryConfig {
    fn flag(self) -> &'static str {
        match self {
            RetryConfig::UnusableAead => "unusable-aead",
            RetryConfig::PqKem => "pq-kem",
            RetryConfig::UnknownVersion => "unknown-version",
            RetryConfig::BadPublicName => "bad-public-name",
            RetryConfig::Malformed => "malformed",
            RetryConfig::Stale => "stale",
            RetryConfig::TruncatedKem => "truncated-kem",
            RetryConfig::TruncatedKey => "truncated-key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadRetryLasts {
    Forever,
    Connections(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchMode {
    On,
    Off,
    BadRetry {
        kind: RetryConfig,
        lasts: BadRetryLasts,
    },
}

impl EchMode {
    fn args(self) -> Vec<String> {
        let mut args = vec!["-ech".to_owned()];
        match self {
            EchMode::On => args.push("on".to_owned()),
            EchMode::Off => args.push("off".to_owned()),
            EchMode::BadRetry { kind, lasts } => {
                let connections = match lasts {
                    BadRetryLasts::Forever => ECH_STUB_BAD_FOREVER,
                    BadRetryLasts::Connections(n) => n,
                };
                args.push("on".to_owned());
                args.extend(["-retry".to_owned(), kind.flag().to_owned()]);
                args.extend(["-bad-connections".to_owned(), connections.to_string()]);
            }
        }
        args
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub ech_accepted: bool,
    pub outer_sni: Option<String>,
    // "Inner" SNI as seen by the Go proxy
    pub sni_seen: Option<String>,
}

struct EchStubReady {
    port: u16,
    ca_der: Vec<u8>,
    ech_config_list: Vec<u8>,
}

pub struct GoEchStub {
    child: Child,
    ready: EchStubReady,
    handshakes: Arc<Mutex<BTreeMap<u64, Handshake>>>,
}

impl GoEchStub {
    pub fn spawn(
        upstream_port: u16,
        public_name: &str,
        tls_domain: Option<&str>,
        ech: EchMode,
    ) -> Self {
        let upstream = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, upstream_port));
        let mut command = ProcessCommand::new("go");
        command
            .args(["run", "."])
            .args(["-upstream", &upstream.to_string()])
            .args(["-public-name", public_name])
            .args(ech.args())
            .arg("-v");
        if let Some(tls_domain) = tls_domain {
            command.args(["-tls-domain", tls_domain]);
        }
        if let Some(path) = std::env::var_os(ECH_STUB_KEYLOG_ENV) {
            command.arg("-keylog").arg(path);
        }

        let mut child = command
            .current_dir(ECH_STUB_DIR)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("ECH tests need go 1.27+ on PATH: {e}"));

        // Spawned from the test thread so libtest captures the forwarded lines
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || forward_ech_stub_stderr(stderr));

        let stdout = child.stdout.take().unwrap();
        let handshakes = Arc::new(Mutex::new(BTreeMap::new()));
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

    pub fn config(&self) -> Config {
        let config = Config::new();
        config.set_root_certificate_override(Some(self.ca_der().to_vec()));
        config
    }

    pub fn handshakes(&self) -> Vec<Handshake> {
        self.handshakes.lock().values().cloned().collect()
    }

    // Returns first `count` connection's handshakes
    pub fn wait_for_handshakes(&self, count: usize) -> Vec<Handshake> {
        let deadline = Instant::now() + MAX_WAIT_TIME;
        while !first_connections_reported(&self.handshakes.lock(), count)
            && Instant::now() < deadline
        {
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

fn first_connections_reported(handshakes: &BTreeMap<u64, Handshake>, count: usize) -> bool {
    // Under heavy load, the handshakes could be re-ordered in rare occasions
    let first = (1..).take(count);
    handshakes.keys().copied().take(count).eq(first)
}

fn forward_ech_stub_stderr(stderr: ChildStderr) {
    for line in BufReader::new(stderr).lines() {
        let Ok(line) = line else {
            return;
        };
        log::debug!(target: ECH_STUB_LOG_TARGET, "{line}");
    }
}

fn read_ech_stub_output(
    stdout: ChildStdout,
    ready_tx: &Sender<EchStubReady>,
    handshakes: &Mutex<BTreeMap<u64, Handshake>>,
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
            Some(ECH_STUB_HANDSHAKE) => {
                let (connection, handshake) = parse_handshake(fields);
                handshakes.lock().insert(connection, handshake);
            }
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

fn parse_handshake(mut fields: SplitWhitespace) -> (u64, Handshake) {
    let connection = fields.next().unwrap().parse().unwrap();
    let ech_accepted = fields.next().unwrap().parse().unwrap();
    let sni_seen = parse_name(fields.next().unwrap());
    let outer_sni = parse_name(fields.next().unwrap());

    let handshake = Handshake {
        ech_accepted,
        outer_sni,
        sni_seen,
    };

    (connection, handshake)
}

fn parse_name(field: &str) -> Option<String> {
    match field {
        ECH_STUB_NONE => None,
        name => Some(name.to_owned()),
    }
}
