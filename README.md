# libens

Client-side library for accessing Error Notification Service on the VPN servers.
Supports servers using NordLynx, NordWhisper and OpenVPN.

## Wire format

The protobuf definition is in [llt-proto](https://github.com/NordSecurity/llt-proto/blob/main/ens/ens.proto).
The version in use is pinned in `crates/ens-core/Cargo.toml`.

## Layout

- `crates/ens-core` - the implementation
- `.` (`libens`) - `cdylib` wrapper, UniFFI scaffolding generated from `ens.udl`
- `cli` (`ens-cli`) - tool for manual testing

## Building

Needs the `protoc` compiler, used by `llt-proto` to compile the wire format.

```sh
cargo build --all
cargo build --release --lib   # only the shared library
```

## CI

Every push builds all platforms via `ci/build.py`, which wraps the
`rust_build_utils` submodule, then triggers the GitLab `libens-build` pipeline
to publish the artifacts. A `v*` semver tag publishes a release; anything else
publishes a `<sha>-SNAPSHOT`.

Initialise the submodule before building locally:

```sh
git submodule update --init --recursive
```

Builds run inside the `ghcr.io/nordsecurity/build-*` images — see
`.github/workflows/build.yml` for the invocations.

## Testing

```sh
cargo test --all --all-features
```

To collect merged coverage from unit and integration tests into
`target/llvm-cov/html/index.html`:

```sh
cargo llvm-cov --all --all-features --exclude ens-cli --html
```

To run lints:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --package libens --package ens-core -- --deny warnings
cargo deny check
```

## CLI

`ens-cli` resolves servers and credentials through the NordVPN API, then opens
an ENS session with this library. Log level is set with `-l`, default `debug`.

```sh
cargo run -p ens-cli -- --help
```

### Finding a server

`list` prints online servers. The optional filter is an id, an IP, a technology
(`wireguard`, `nordwhisper`, `openvpnudp`, `openvpntcp`, `openvpnudpobfuscated`,
`openvpntcpobfuscated`) or a hostname:

```sh
cargo run -p ens-cli -- list wireguard
cargo run -p ens-cli -- show hostname uk2040.nordvpn.com
cargo run -p ens-cli -- show ip 185.16.207.58
```

### Connecting

`connect` takes the server IP with the ENS port, and an access token via `--token` or `NORD_TOKEN`:

```sh
export NORD_TOKEN=...
cargo run -p ens-cli -- connect 185.16.207.58:993 --kind nord-lynx --duration 60
```

Notifications and disconnects are logged to stderr. The process exits once the
server disconnects, or after `--duration` seconds, default 15.
