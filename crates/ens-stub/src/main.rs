//! Standalone ENS server stub driven over stdin, for the integration tests of
//! the bindings.
//!
//! The authentication schema is chosen with the first argument, `nordlynx` by
//! default:
//!
//! ```sh
//! ens-stub [nordlynx|nordwhisper|openvpn]
//! ```
//!
//! On startup a single json line with the connection details is written to
//! stdout. `username` and `password` are only present for the credentials
//! based schemas, and the client has to send exactly those:
//!
//! ```json
//! {"port":40913,"public_key":"<base64>","root_certificate":"<base64 DER>","username":"<generated>","password":"<generated>"}
//! ```
//!
//! Every subsequent line read from stdin is a command:
//!
//! ```json
//! {"command":"notification","code":2,"additional_info":"planned maintenance"}
//! {"command":"error","message":"some message"}
//! {"command":"end"}
//! ```
//!
//! The stub terminates on stdin EOF.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::error::Error;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use clap::{Parser, ValueEnum};
use ens_stub::{spawn_server, Command, ExpectedAuth, ServerConfig};
use log::warn;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tonic::Status;

use llt_proto::ens::ConnectionError;

#[derive(Parser)]
struct Args {
    /// Authentication schema the stub expects from the client
    #[arg(value_enum, default_value_t = Schema::Nordlynx)]
    schema: Schema,
}

#[derive(Clone, ValueEnum)]
#[value(rename_all = "lower")]
enum Schema {
    Nordlynx,
    Nordwhisper,
    Openvpn,
}

impl From<Schema> for ExpectedAuth {
    fn from(value: Schema) -> Self {
        match value {
            Schema::Nordlynx => ExpectedAuth::any_nordlynx(),
            Schema::Nordwhisper => ExpectedAuth::new_nordwhisper(),
            Schema::Openvpn => ExpectedAuth::new_openvpn(),
        }
    }
}

#[derive(Serialize)]
struct Handshake {
    port: u16,
    public_key: String,
    root_certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum StubCommand {
    Notification {
        code: i32,
        additional_info: Option<String>,
    },
    Error {
        message: String,
    },
    End,
}

impl From<StubCommand> for Command {
    fn from(value: StubCommand) -> Self {
        match value {
            StubCommand::Notification {
                code,
                additional_info,
            } => Command::Send(ConnectionError {
                code,
                additional_info,
            }),
            StubCommand::Error { message } => Command::Error(Status::unknown(message)),
            StubCommand::End => Command::End,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let auth = ExpectedAuth::from(Args::parse().schema);
    let server = spawn_server(auth.clone(), None).await?;
    announce(&server, &auth)?;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<StubCommand>(&line) {
            Ok(command) => server.send(command.into()).await,
            Err(e) => warn!("Ignoring {line:?}: {e}"),
        }
    }

    Ok(())
}

fn announce(server: &ServerConfig, auth: &ExpectedAuth) -> Result<(), Box<dyn Error>> {
    let (username, password) = match auth.credentials() {
        Some((username, password)) => (Some(username.to_owned()), Some(password.to_owned())),
        None => (None, None),
    };

    let handshake = Handshake {
        port: server.port,
        public_key: BASE64_STANDARD.encode(server.public_key),
        root_certificate: BASE64_STANDARD.encode(server.tls_config.ca_cert.der()),
        username,
        password,
    };

    println!("{}", serde_json::to_string(&handshake)?);

    Ok(())
}
