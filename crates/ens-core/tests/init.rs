use assert_matches::assert_matches;
use ens_core::{init, EnsError};

const APP_VERSION: &str = "init-tests";

#[test_log::test]
fn second_init_fails() {
    init(APP_VERSION.to_owned()).unwrap();

    assert_matches!(
        init(APP_VERSION.to_owned()),
        Err(EnsError::AlreadyInitialized)
    );
}
