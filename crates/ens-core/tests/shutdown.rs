#[path = "../src/test_support.rs"]
mod test_support;

use ens_core::{deinit, ConnectionErrorNotification, ConnectionErrorNotificationKind};
use llt_proto::ens::{ConnectionError, Error as EnsProtoError};
use tokio::runtime::Runtime;

use test_support::{
    connect_to_test_server, run_init, spawn_server, wait_for, Command, RecordedCallback,
    SHUTDOWN_REASON,
};

const MAINTENANCE_INFO: &str = "planned maintenance";

#[test_log::test]
fn deinit_shuts_down_active_connections() {
    // The server has to outlive `deinit`, so it gets a runtime of its own.
    let server_runtime = Runtime::new().unwrap();
    let server_config = server_runtime.block_on(spawn_server());

    run_init();

    let callback = RecordedCallback::default();
    let _connection = connect_to_test_server(&server_config, callback.clone());

    server_config.send_blocking(Command::Send(ConnectionError {
        code: EnsProtoError::ServerMaintenance as i32,
        additional_info: Some(MAINTENANCE_INFO.to_owned()),
    }));

    wait_for(|| !callback.notifications.lock().is_empty());

    deinit().unwrap();

    wait_for(|| callback.disconnected.lock().is_some());

    assert_eq!(
        *callback.disconnected.lock(),
        Some(Some(SHUTDOWN_REASON.to_owned()))
    );
    assert_eq!(
        *callback.notifications.lock(),
        vec![ConnectionErrorNotification {
            kind: ConnectionErrorNotificationKind::ServerMaintenance,
            additional_info: Some(MAINTENANCE_INFO.to_owned()),
        }]
    );
}
