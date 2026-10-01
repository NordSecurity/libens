# libens

Client-side library for accessing Error Notification Service on the VPN servers.
Supports servers using NordLynx, NordWhisper and OpenVPN.

## Wire format

The protobuf definition is in [llt-proto](https://github.com/NordSecurity/llt-proto/blob/main/ens/ens.proto).
The version in use is pinned in `crates/ens-core/Cargo.toml`.

## Layout

- `crates/ens-core` - the implementation
- `crates/ens-stub` - fake ENS server the tests run against
- `.` (`libens`) - `cdylib` wrapper, UniFFI scaffolding generated from `ens.udl`
- `cli` (`ens-cli`) - tool for manual testing
- `tests/go` - integration tests for the generated go bindings
- `doc/integrating_libens.md` - integration guide for app developers

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
cargo llvm-cov --all --all-features --exclude ens-cli --exclude ens-stub --ignore-filename-regex ens-core/src/test_support --html
```

To run lints:

```sh
cargo fmt -- --check
cargo clippy --all-targets --all-features --package libens --package ens-core --package ens-stub -- --deny warnings
cargo deny check
```

### ENS stub

`ens-stub` is a fake ENS server. It speaks the real wire format and checks
authentication the same way a real server does, but the notifications it sends
are the ones a test asks for.

`spawn_server` picks the authentication schema, `ExpectedAuth`, and starts a
server on a free port. Commands are queued, so a test can send them before the
client connects.

The bindings tests drive the same stub as a binary, over stdin and stdout:

1. The first argument picks the authentication schema - `nordlynx` (the
   default), `nordwhisper` or `openvpn`.
2. On startup the stub prints one json line with everything needed to connect.
   The password based schemas also print the credentials they expect.
3. Every line written to stdin is a command.
4. Closing stdin stops the stub.

```sh
cargo run --package ens-stub -- openvpn
```

Printed on startup:

```json
{"port":40913,"public_key":"<base64>","root_certificate":"<base64 DER>","username":"<generated>","password":"<generated>"}
```

Commands read from stdin, one per line:

```json
{"command":"notification","code":2,"additional_info":"planned maintenance"}
{"command":"error","message":"some message"}
{"command":"end"}
```

`notification` delivers one error notification, `error` fails the stream with a
grpc error and `end` closes the stream.

### Bindings tests

`tests/go` drives the stub through the generated go bindings, one test per
authentication schema and one for a rejected authentication. Linux only.

The bindings are part of `libens-bindings` workflow job.

```sh
uniffi-bindgen-go ./ens.udl --config uniffi.toml --out-dir libens-bindings/linux/go
cp tests/go/bindings.mod libens-bindings/linux/go/go.mod
```

The tests load `libens.so` and spawn the stub:

```sh
cargo build --package libens --package ens-stub
cd tests/go
export CGO_CFLAGS="-I$PWD/../../libens-bindings/linux/go/ens"
export CGO_LDFLAGS="-L$PWD/../../target/debug -lens -Wl,-rpath,$PWD/../../target/debug"
go test ./...
```

`ENS_STUB` overrides the stub binary path.

`tests/cs` drives the stub through the generated c# bindings. The generator
emits `internal` types, so the bindings are compiled into the test assembly
rather than referenced as a package. Linux only, against the released
`libens.so`.

```sh
uniffi-bindgen-cs ./ens.udl --config uniffi.toml --out-dir dist/windows/cs
mkdir -p tests/cs/bindings
cp dist/windows/cs/ens.cs tests/cs/bindings/
python3 ci/build.py build linux x86_64
cargo build --package ens-stub
```

```sh
cd tests/cs
export LD_LIBRARY_PATH="$PWD/../../dist/linux/release/x86_64"
export ENS_STUB="$PWD/../../target/debug/ens-stub"
dotnet test
```

`tests/kotlin` drives the stub through the generated kotlin bindings, as android
instrumented tests on an x86_64 emulator. The stub is cross compiled for android
and shipped inside the test apk as a jni library, because android only executes
binaries from the directory the apk was unpacked into.

```sh
uniffi-bindgen generate ./ens.udl --language kotlin --config uniffi.toml --out-dir dist/android/kotlin
cargo build --package ens-stub --target x86_64-linux-android
python3 ci/build.py build android x86_64
```

The bindings, `libens.so` and the stub are copied into the test project, which
then runs against a booted emulator:

```sh
JNI_LIBS=tests/kotlin/lib/src/androidTest/jniLibs/x86_64
mkdir -p "$JNI_LIBS"
cp dist/android/kotlin/com/nordsec/ens/ens.kt tests/kotlin/lib/src/androidTest/kotlin/com/nordsec/ens/
cp dist/android/release/x86_64/libens.so "$JNI_LIBS"
cp target/x86_64-linux-android/debug/ens-stub "$JNI_LIBS/libens_stub.so"
gradle -p tests/kotlin :lib:connectedDebugAndroidTest
```

The library logs under the `libens` tag and the stub under `ens-stub`:

```sh
adb logcat -d -s libens:V ens-stub:V
```

`tests/swift` drives the stub through the generated swift bindings, linked
against the same `libensFFI.xcframework` that is shipped to consumers. Macos
only, and the xcframework covers every apple platform, so all of its slices
have to be built first:

```sh
uniffi-bindgen generate ./ens.udl --language swift --config uniffi.toml --out-dir dist/apple/Sources
for slice in "macos x86_64" "macos aarch64" "ios aarch64" "ios-sim aarch64" \
             "ios-sim x86_64" "tvos aarch64" "tvos-sim aarch64" "tvos-sim x86_64"; do
    python3 ci/build.py build $slice
done
python3 ci/build.py lipo
python3 ci/build.py xcframework
```

The bindings and the xcframework are copied into the test package, which spawns
the stub itself:

```sh
mkdir -p tests/swift/Sources/EnsSwift tests/swift/Frameworks
cp dist/apple/Sources/ens.swift tests/swift/Sources/EnsSwift/
cp -R dist/darwin/libensFFI.xcframework tests/swift/Frameworks/
cargo build --package ens-stub
ENS_STUB="$PWD/target/debug/ens-stub" swift test --package-path tests/swift
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

## Trademarks

*libens is not affiliated with gRPC®. gRPC® is a registered trademark owned by The Linux Foundation*
