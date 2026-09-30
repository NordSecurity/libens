#[path = "../src/test_support/mod.rs"]
mod test_support;

use ens_core::runtime::get_runtime;

use test_support::{
    connect_local, maintenance, run_init, spawn_plain_server, test_auth, wait_for, EchMode,
    GoEchStub, Handshake, RecordedCallback, TcpRelay,
};

const MAINTENANCE_INFO: &str = "planned maintenance";
const ECH_PUBLIC_NAME: &str = "cover.example.com";
const TLS_DOMAIN: &str = "secret.example.com";

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
