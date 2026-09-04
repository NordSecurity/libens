#[path = "../src/test_support.rs"]
mod test_support;

use std::sync::Arc;

use ens_core::{deinit, Connection};
use llt_proto::ens::{ConnectionError, Error as EnsProtoError};
use tokio::runtime::Runtime;

use test_support::{
    connect_to_test_server, run_init, spawn_server, wait_for, Command, RecordedCallback,
    ServerConfig, SHUTDOWN_REASON,
};

const FIRST: &str = "first";
const SECOND: &str = "second";
const THIRD: &str = "third";
const SECOND_AGAIN: &str = "second again";

fn maintenance(info: &str) -> Command {
    Command::Send(ConnectionError {
        code: EnsProtoError::ServerMaintenance as i32,
        additional_info: Some(info.to_owned()),
    })
}

fn infos(callback: &RecordedCallback) -> Vec<Option<String>> {
    callback
        .notifications
        .lock()
        .iter()
        .map(|n| n.additional_info.clone())
        .collect()
}

fn connect_and_notify(server: &ServerConfig, info: &str) -> (Arc<Connection>, RecordedCallback) {
    let callback = RecordedCallback::default();
    let connection = connect_to_test_server(server, callback.clone());

    server.send_blocking(maintenance(info));
    wait_for(|| !callback.notifications.lock().is_empty());

    (connection, callback)
}

#[test_log::test]
fn multiple_connections_at_the_same_time() {
    let runtime = Runtime::new().unwrap();
    let first_server = runtime.block_on(spawn_server());
    let second_server = runtime.block_on(spawn_server());
    let third_server = runtime.block_on(spawn_server());

    run_init();

    let (first, first_callback) = connect_and_notify(&first_server, FIRST);
    let (_second, second_callback) = connect_and_notify(&second_server, SECOND);
    let (_third, third_callback) = connect_and_notify(&third_server, THIRD);

    assert_eq!(infos(&first_callback), vec![Some(FIRST.to_owned())]);
    assert_eq!(infos(&second_callback), vec![Some(SECOND.to_owned())]);
    assert_eq!(infos(&third_callback), vec![Some(THIRD.to_owned())]);

    first.shutdown().unwrap();
    wait_for(|| !first_callback.disconnects.lock().is_empty());
    assert_eq!(
        *first_callback.disconnects.lock(),
        vec![Some(SHUTDOWN_REASON.to_owned())]
    );
    assert!(second_callback.disconnects.lock().is_empty());
    assert!(third_callback.disconnects.lock().is_empty());

    second_server.send_blocking(maintenance(SECOND_AGAIN));
    wait_for(|| second_callback.notifications.lock().len() == 2);
    assert_eq!(
        infos(&second_callback),
        vec![Some(SECOND.to_owned()), Some(SECOND_AGAIN.to_owned())]
    );
    assert_eq!(infos(&first_callback), vec![Some(FIRST.to_owned())]);
    assert_eq!(infos(&third_callback), vec![Some(THIRD.to_owned())]);

    deinit().unwrap();
    wait_for(|| {
        !second_callback.disconnects.lock().is_empty()
            && !third_callback.disconnects.lock().is_empty()
    });
    assert_eq!(
        *second_callback.disconnects.lock(),
        vec![Some(SHUTDOWN_REASON.to_owned())]
    );
    assert_eq!(
        *third_callback.disconnects.lock(),
        vec![Some(SHUTDOWN_REASON.to_owned())]
    );
    assert_eq!(first_callback.disconnects.lock().len(), 1);
}
