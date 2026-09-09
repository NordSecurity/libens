#[path = "../src/test_support.rs"]
mod test_support;

use std::sync::Arc;

use assert_matches::assert_matches;
use ens_core::{
    deinit, get_memory_usage, get_version, init, Authentication, Connection,
    ConnectionErrorNotification, ConnectionErrorNotificationKind, EnsError, Hidden, KeyKind, Keys,
};
use llt_proto::ens::{ConnectionError, Error as EnsProtoError};
use telio_crypto::SecretKey;
use tokio::runtime::Runtime;

use test_support::{
    connect_to_test_server, run_init, spawn_server, wait_for, Command, RecordedCallback,
    ServerConfig, SHUTDOWN_REASON,
};

use crate::test_support::connect_to_test_server_with_auth;

const APP_VERSION: &str = "deinit-tests";
const MAINTENANCE_INFO: &str = "planned maintenance";

fn test_auth(server_config: &ServerConfig) -> Authentication {
    Authentication::WithKeys {
        keys: Keys {
            local_private_key: Hidden(SecretKey::gen().to_vec()),
            vpn_public_key: Hidden(server_config.public_key.to_vec()),
            kind: KeyKind::NordLynx,
        },
    }
}

fn connect_and_await_first_notification(
    server_config: &ServerConfig,
) -> (Arc<Connection>, RecordedCallback) {
    let callback = RecordedCallback::default();
    let connection = connect_to_test_server(server_config, callback.clone());

    server_config.send_blocking(Command::Send(ConnectionError {
        code: EnsProtoError::ServerMaintenance as i32,
        additional_info: Some(MAINTENANCE_INFO.to_owned()),
    }));
    wait_for(|| !callback.notifications.lock().is_empty());

    assert_eq!(
        *callback.notifications.lock(),
        vec![ConnectionErrorNotification {
            kind: ConnectionErrorNotificationKind::ServerMaintenance,
            additional_info: Some(MAINTENANCE_INFO.to_owned()),
        }]
    );

    (connection, callback)
}

#[test_log::test]
fn nothing_works_after_deinit() {
    // The servers have to outlive `deinit`, so it needs separate runtime.
    let server_runtime = Runtime::new().unwrap();
    let first_server = server_runtime.block_on(spawn_server());
    let second_server = server_runtime.block_on(spawn_server());

    run_init();

    let (connection, callback) = connect_and_await_first_notification(&first_server);

    deinit().unwrap();

    wait_for(|| !callback.disconnects.lock().is_empty());
    assert_eq!(
        *callback.disconnects.lock(),
        vec![Some(SHUTDOWN_REASON.to_owned())]
    );

    assert_matches!(deinit(), Err(EnsError::NotInitialized { .. }));

    let rejected_callback = RecordedCallback::default();

    assert_matches!(
        connect_to_test_server_with_auth(
            &second_server,
            test_auth(&second_server),
            rejected_callback.clone()
        ),
        Err(EnsError::NotInitialized { .. })
    );
    assert!(rejected_callback.notifications.lock().is_empty());
    assert!(rejected_callback.disconnects.lock().is_empty());

    assert_matches!(connection.shutdown(), Ok(()));
    assert_eq!(callback.disconnects.lock().len(), 1);

    // Both can be used before init/after deinit:
    assert!(get_version().starts_with('v'));
    let _ = get_memory_usage();

    init(APP_VERSION.to_owned()).unwrap();

    let (_reconnected, callback_after_reinit) =
        connect_and_await_first_notification(&second_server);
    assert!(callback_after_reinit.disconnects.lock().is_empty());

    deinit().unwrap();
    wait_for(|| !callback_after_reinit.disconnects.lock().is_empty());
    assert_eq!(
        *callback_after_reinit.disconnects.lock(),
        vec![Some(SHUTDOWN_REASON.to_owned())]
    );
}
