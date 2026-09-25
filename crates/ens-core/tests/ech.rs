#[path = "../src/test_support/mod.rs"]
mod test_support;

use ens_core::{runtime::get_runtime, Config};
use rstest::rstest;
use tonic::Status;

use test_support::{
    connect_local, maintenance, run_init, spawn_plain_server, test_auth, wait_for,
    wait_for_disconnect_reason, BadRetryLasts, Command, EchMode, GoEchStub, Handshake,
    RecordedCallback, RetryConfig, TcpRelay,
};

const MAINTENANCE_INFO: &str = "planned maintenance";
const ECH_PUBLIC_NAME: &str = "cover.example.com";
const TLS_DOMAIN: &str = "secret.example.com";
const REJECTION_MESSAGE: &str = "token revoked";
const BACKOFF_SECONDS: u32 = 1;
const ECH_HANDSHAKES_PER_CONNECTION: usize = 2;
const ECH_CONNECTIONS: usize = 2;
const ECH_BOOTSTRAPPING_REJECTED: &str = "ECH bootstrapping rejected";

fn fast_backoff(config: Config) -> Config {
    config.set_backoff_initial(BACKOFF_SECONDS);
    config.set_backoff_maximal(Some(BACKOFF_SECONDS));
    config
}

#[test_log::test]
fn plain_tls_through_go_stub() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(upstream.port, ECH_PUBLIC_NAME, None, EchMode::Off);

    let callback = RecordedCallback::default();
    let config = stub.config();
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    upstream.send_blocking(maintenance(MAINTENANCE_INFO));
    wait_for(|| !callback.notifications.lock().is_empty());

    assert_eq!(callback.infos(), vec![Some(MAINTENANCE_INFO.to_owned())]);
    assert!(callback.disconnects.lock().is_empty());
    assert_eq!(
        stub.wait_for_handshakes(1),
        vec![Handshake {
            ech_accepted: false,
            sni_seen: None,
            outer_sni: None,
        }]
    );
}

#[test_log::test]
fn ech_bootstrap_rejects_cert_valid_only_for_public_name() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(upstream.port, ECH_PUBLIC_NAME, None, EchMode::On);

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    let reason = wait_for_disconnect_reason(&callback).unwrap();
    assert!(reason.contains("untrusted certificate"));
    assert!(reason.contains("not valid for name"));
    assert_eq!(stub.wait_for_handshakes(1).len(), 1);
    assert_eq!(upstream.streams(), 0);
    assert!(callback.notifications.lock().is_empty());
}

#[test_log::test]
fn ech_bootstraps_from_retry_configs() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::On,
    );

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    let handshakes = stub.wait_for_handshakes(2);
    assert_eq!(handshakes.len(), 2);
    wait_for(|| upstream.streams() == 1);
    assert!(callback.disconnects.lock().is_empty());

    let bootstrap = &handshakes[0];
    assert!(!bootstrap.ech_accepted);
    let cover_name = bootstrap.outer_sni.clone().unwrap();
    assert_ne!(cover_name, ECH_PUBLIC_NAME);
    assert_eq!(bootstrap.sni_seen, Some(cover_name));

    assert_eq!(
        handshakes[1],
        Handshake {
            ech_accepted: true,
            sni_seen: Some(TLS_DOMAIN.to_owned()),
            outer_sni: Some(ECH_PUBLIC_NAME.to_owned()),
        }
    );

    upstream.send_blocking(maintenance(MAINTENANCE_INFO));
    wait_for(|| !callback.notifications.lock().is_empty());

    assert_eq!(callback.infos(), vec![Some(MAINTENANCE_INFO.to_owned())]);
}

#[test_log::test]
fn ech_bootstrap_repeats_after_stream_error() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::On,
    );

    let callback = RecordedCallback::default();
    let config = fast_backoff(stub.config());
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    wait_for(|| upstream.streams() == 1);
    upstream.send_blocking(Command::Error(Status::internal(REJECTION_MESSAGE)));
    wait_for(|| upstream.streams() == ECH_CONNECTIONS);

    let handshakes = stub.wait_for_handshakes(ECH_HANDSHAKES_PER_CONNECTION * ECH_CONNECTIONS);
    assert_eq!(
        handshakes.len(),
        ECH_HANDSHAKES_PER_CONNECTION * ECH_CONNECTIONS
    );

    for connection in handshakes.chunks(ECH_HANDSHAKES_PER_CONNECTION) {
        assert!(!connection[0].ech_accepted);
        assert_ne!(connection[0].outer_sni.as_deref(), Some(ECH_PUBLIC_NAME));
        assert_eq!(
            connection[1],
            Handshake {
                ech_accepted: true,
                sni_seen: Some(TLS_DOMAIN.to_owned()),
                outer_sni: Some(ECH_PUBLIC_NAME.to_owned()),
            }
        );
    }

    upstream.send_blocking(maintenance(MAINTENANCE_INFO));
    wait_for(|| !callback.notifications.lock().is_empty());

    assert_eq!(callback.infos(), vec![Some(MAINTENANCE_INFO.to_owned())]);
    assert!(callback.disconnects.lock().is_empty());
}

#[test_log::test]
fn ech_bootstrap_keeps_tls_domain_off_wire() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::On,
    );
    let relay = runtime.block_on(TcpRelay::spawn(stub.port()));

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    let _connection =
        connect_local(relay.port, test_auth(&upstream), callback.clone(), config).unwrap();

    upstream.send_blocking(maintenance(MAINTENANCE_INFO));
    wait_for(|| !callback.notifications.lock().is_empty());

    let handshakes = stub.wait_for_handshakes(2);
    assert_eq!(handshakes.len(), 2, "handshakes: {handshakes:?}");
    assert!(handshakes[1].ech_accepted);
    assert_eq!(handshakes[1].sni_seen, Some(TLS_DOMAIN.to_owned()));

    let wire = relay.wire();
    assert!(wire.contains(ECH_PUBLIC_NAME));
    assert!(!wire.contains(TLS_DOMAIN));
}

#[test_log::test]
fn plain_tls_leaks_tls_domain_on_wire() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::Off,
    );
    let relay = runtime.block_on(TcpRelay::spawn(stub.port()));

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    let _connection =
        connect_local(relay.port, test_auth(&upstream), callback.clone(), config).unwrap();

    upstream.send_blocking(maintenance(MAINTENANCE_INFO));
    wait_for(|| !callback.notifications.lock().is_empty());

    assert_eq!(
        stub.wait_for_handshakes(1),
        vec![Handshake {
            ech_accepted: false,
            sni_seen: Some(TLS_DOMAIN.to_owned()),
            outer_sni: Some(TLS_DOMAIN.to_owned()),
        }]
    );
    assert!(relay.wire().contains(TLS_DOMAIN));
}

#[rstest]
#[case(RetryConfig::UnusableAead)]
#[case(RetryConfig::PqKem)]
#[case(RetryConfig::UnknownVersion)]
#[case(RetryConfig::BadPublicName)]
#[case(RetryConfig::TruncatedKem)]
#[case(RetryConfig::TruncatedKey)]
#[test_log::test]
fn ech_retry_config_client_cannot_use_triggers_disconnect(#[case] kind: RetryConfig) {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::BadRetry {
            kind,
            lasts: BadRetryLasts::Forever,
        },
    );

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    config.set_backoff_initial(BACKOFF_SECONDS);
    config.set_backoff_maximal(Some(BACKOFF_SECONDS));
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    wait_for(|| !callback.disconnects.lock().is_empty());
    assert_eq!(upstream.streams(), 0);
    assert!(callback.notifications.lock().is_empty());
}

#[test_log::test]
fn ech_offer_ignored_by_plain_server_triggers_disconnect() {
    run_init();

    let runtime = get_runtime().unwrap();
    let upstream = runtime.block_on(spawn_plain_server());
    let stub = GoEchStub::spawn(
        upstream.port,
        ECH_PUBLIC_NAME,
        Some(TLS_DOMAIN),
        EchMode::Off,
    );

    let callback = RecordedCallback::default();
    let config = stub.config();
    config.set_tls_domain(Some(TLS_DOMAIN.to_owned()));
    config.set_enable_ech_bootstrap(true);
    config.set_backoff_initial(BACKOFF_SECONDS);
    config.set_backoff_maximal(Some(BACKOFF_SECONDS));
    let _connection =
        connect_local(stub.port(), test_auth(&upstream), callback.clone(), config).unwrap();

    let handshakes = stub.wait_for_handshakes(1);
    assert!(!handshakes[0].ech_accepted);
    assert_ne!(handshakes[0].sni_seen, Some(TLS_DOMAIN.to_owned()));

    let reason = wait_for_disconnect_reason(&callback).unwrap();
    assert!(reason.contains(ECH_BOOTSTRAPPING_REJECTED));

    assert_eq!(upstream.streams(), 0);
    assert!(callback.notifications.lock().is_empty());
}
