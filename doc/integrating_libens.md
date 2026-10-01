<!-- markdownlint-disable MD033 -->

# Integrating libens

For NordVPN app developers. Apps use libens only through the bindings
generated from [`ens.udl`](../ens.udl):

| Language | Bindings                             | Import                                              |
|----------|--------------------------------------|-----------------------------------------------------|
| Go       | `uniffi-bindgen-go`                  | `github.com/NordSecurity/libens/bindings/go/ens`    |
| Swift    | `uniffi-bindgen --language swift`    | module name set by the app's package, `EnsSwift` below |
| C#       | `uniffi-bindgen-cs`                  | `uniffi.ens`                                        |
| Kotlin   | `uniffi-bindgen --language kotlin`   | `com.nordsec.ens`                                   |

Examples skip error handling for brevity.

## Lifecycle

1. `set_log_callback` - optional, once per process.
2. `init` - once per process.
3. `connect` - one `Connection` per VPN connection.
4. `Connection.shutdown` - when the VPN connection ends.
5. `deinit` - when the app no longer needs ENS.

## Log Callback

Registers the log sink. Only messages at or below `max_level` are passed.
Can be called before `init` to see its logs. Works once per process and a second
call fails with `InternalError` while keeping the first callback. Release builds
replace sensitive data in messages with dots.

<multi-code-select></multi-code-select>

<multi-code>

```go
import "github.com/NordSecurity/libens/bindings/go/ens"

type Logger struct{}

func (l Logger) Log(logLevel ens.LogLevel, message string) {
    // pass to the app logger
}

err := ens.SetLogCallback(ens.LogLevelDebug, Logger{})
```

```swift
import EnsSwift

class Logger: LogCallback {
    func log(logLevel: LogLevel, message: String) {
        // pass to the app logger
    }
}

try setLogCallback(maxLevel: .debug, callback: Logger())
```

```cs
using uniffi.ens;

class Logger : LogCallback {
    public void Log(LogLevel logLevel, string message) {
        // pass to the app logger
    }
}

EnsMethods.SetLogCallback(LogLevel.Debug, new Logger());
```

```kotlin
import com.nordsec.ens.*

val logger = object : LogCallback {
    override fun log(logLevel: LogLevel, message: String) {
        // pass to the app logger
    }
}

setLogCallback(LogLevel.DEBUG, logger)
```

</multi-code>

## Init / Deinit

`init` takes a short string naming the app and its version, e.g.
`nordvpn-android/7.1.0`. It is sent to the server in the user agent. A second
`init` without `deinit` fails with `AlreadyInitialized`.

After `deinit` returns, operations that require initialized library state, such
as `connect` and another `deinit`, fail with `NotInitialized` until `init` is
called again. Process-level and diagnostic functions such as `get_version`,
`get_memory_usage`, and the initial `set_log_callback` call do not follow this
rule.

<multi-code-select></multi-code-select>

<multi-code>

```go
err := ens.Init("nordvpn-linux/4.0.0")
err = ens.Deinit()
```

```swift
try EnsSwift.`init`(appVersion: "nordvpn-ios/9.0.0")
try EnsSwift.`deinit`()
```

```cs
EnsMethods.Init("nordvpn-windows/7.0.0");
EnsMethods.Deinit();
```

```kotlin
`init`("nordvpn-android/7.1.0")
`deinit`()
```

</multi-code>

`get_version` returns the library version as `vX.Y.Z`. `get_memory_usage`
returns the library heap usage in bytes, for diagnostics.

## Config

`connect` copies the config, so later changes apply only to new connections.

| Setter                          | Default | Meaning                                                                          |
|---------------------------------|---------|----------------------------------------------------------------------------------|
| `set_buffer_size`               | 5       | Maximum number of pending notifications waiting to be delivered to the callback. Must be non-zero. If the queue is full, each newly received notification is dropped; notifications already queued are preserved. |
| `set_allow_only_pq`             | true    | Offer only the post-quantum X25519MLKEM768 key exchange.                         |
| `set_tls_domain`                | null    | TLS SNI. Null: no SNI, certificate must be valid for the server IP.              |
| `set_enable_ech_bootstrap`      | false   | Encrypted Client Hello. Useful only with `tls_domain`. No fallback to plain TLS. |
| `set_root_certificate_override` | null    | DER root certificate instead of the built-in one. For tests.                     |
| `set_backoff_initial`           | 2s      | First reconnect delay. Doubles on every failure. Must be non zero.               |
| `set_backoff_maximal`           | 120s    | Reconnect delay limit, not below `backoff_initial`. Null: no limit.              |
| `set_keepalive_interval`        | 120s    | Keep alive interval. Null: disabled. 0: default.                                 |
| `set_keepalive_timeout`         | 20s     | Keep alive response timeout. Null: http client default. 0: default.              |
| `set_bootstrap_ech_timeout`     | 30s     | ECH bootstrap limit. 0: default.                                                 |

Invalid backoff bounds are replaced with the library’s fallback backoff configuration (1s with no limit) and logged as a warning.

<multi-code-select></multi-code-select>

<multi-code>

```go
config := ens.NewConfig()
defer config.Destroy()

tlsDomain := "uk2040.nordvpn.com"
config.SetTlsDomain(&tlsDomain)
config.SetEnableEchBootstrap(true)
```

```swift
let config = Config()
config.setTlsDomain(tlsDomain: "uk2040.nordvpn.com")
config.setEnableEchBootstrap(enableEch: true)
```

```cs
var config = new Config();
config.SetTlsDomain("uk2040.nordvpn.com");
config.SetEnableEchBootstrap(true);
```

```kotlin
val config = Config()
config.setTlsDomain("uk2040.nordvpn.com")
config.setEnableEchBootstrap(true)
```

</multi-code>

## Authentication

The variant must match the VPN protocol of the monitored connection.

**NordLynx** - `WithKeys`. Raw 32 byte keys (not base64):

- `local_private_key` - the app's NordLynx private key
  (`nordlynx_private_key` from `/v1/users/services/credentials`).
- `vpn_public_key` - the server's WireGuard public key, the same one used for
  the tunnel (`public_key` in the server's WireGuard technology metadata).

**OpenVPN and NordWhisper** - `WithCredentials`. The service `username` and
`password`. The same ones sent to the VPN server. The username can't contain
`:`.

<multi-code-select></multi-code-select>

<multi-code>

```go
nordLynx := ens.AuthenticationWithKeys{
    Keys: ens.Keys{
        LocalPrivateKey: privateKey,
        VpnPublicKey:    serverPublicKey,
        Kind:            ens.KeyKindNordLynx,
    },
}

openVpn := ens.AuthenticationWithCredentials{
    Credentials: ens.Credentials{
        Username: username,
        Password: password,
        Kind:     ens.CredentialsKindOpenVpn,
    },
}
```

```swift
let nordLynx = Authentication.withKeys(keys: Keys(
    localPrivateKey: privateKey,
    vpnPublicKey: serverPublicKey,
    kind: .nordLynx))

let openVpn = Authentication.withCredentials(credentials: Credentials(
    username: username,
    password: password,
    kind: .openVpn))
```

```cs
var nordLynx = new Authentication.WithKeys(
    new Keys(privateKey, serverPublicKey, KeyKind.NordLynx));

var openVpn = new Authentication.WithCredentials(
    new Credentials(username, password, CredentialsKind.OpenVpn));
```

```kotlin
val nordLynx = Authentication.WithKeys(
    Keys(privateKey, serverPublicKey, KeyKind.NORD_LYNX))

val openVpn = Authentication.WithCredentials(
    Credentials(username, password, CredentialsKind.OPEN_VPN))
```

</multi-code>

## Notification Callback

`notify` is called for every notification from the server, zero or more times.
`disconnected` is called once, when the session ends. The `notify` never follows
it.

Both run on a library thread. Don't block them, move all work to the app's own
threads. An exception thrown from `notify` ends the session.

<multi-code-select></multi-code-select>

<multi-code>

```go
type Handler struct{}

func (h Handler) Notify(notification ens.ConnectionErrorNotification) {
    // pass to the app
}

func (h Handler) Disconnected(reason *string) {
    // pass to the app
}
```

```swift
class Handler: ErrorNotificationCallback {
    func notify(notification: ConnectionErrorNotification) {
        // pass to the app
    }

    func disconnected(reason: String?) {
        // pass to the app
    }
}
```

```cs
class Handler : ErrorNotificationCallback {
    public void Notify(ConnectionErrorNotification notification) {
        // pass to the app
    }

    public void Disconnected(string? reason) {
        // pass to the app
    }
}
```

```kotlin
val handler = object : ErrorNotificationCallback {
    override fun notify(notification: ConnectionErrorNotification) {
        // pass to the app
    }

    override fun disconnected(reason: String?) {
        // pass to the app
    }
}
```

</multi-code>

### Notification kinds

| Kind                     | Meaning                                                        |
|--------------------------|----------------------------------------------------------------|
| `ConnectionLimitReached` | The account reached its device limit.                          |
| `ServerMaintenance`      | Server goes into maintenance.                                  |
| `Unauthenticated`        | The VPN credentials are not valid.                             |
| `Superseded`             | A newer session of the same account connected to this server.  |
| `UnsupportedCipher`      | The server rejected the VPN cipher.                            |
| `Unknown(kind)`          | Not known to this library version. `kind` holds the raw value. |

`additional_info` is optional free text from the VPN server.

<multi-code-select></multi-code-select>

<multi-code>

```go
switch notification.Kind.(type) {
case ens.ConnectionErrorNotificationKindServerMaintenance:
    // reconnect to another server
case ens.ConnectionErrorNotificationKindUnknown:
    // log
default:
    // tell the user
}
```

```swift
switch notification.kind {
case .serverMaintenance:
    // reconnect to another server
case .unknown(let kind):
    // log
default:
    // tell the user
}
```

```cs
switch (notification.kind) {
    case ConnectionErrorNotificationKind.ServerMaintenance:
        // reconnect to another server
        break;
    case ConnectionErrorNotificationKind.Unknown unknown:
        // log
        break;
    default:
        // tell the user
        break;
}
```

```kotlin
when (val kind = notification.kind) {
    is ConnectionErrorNotificationKind.ServerMaintenance -> {} // reconnect to another server
    is ConnectionErrorNotificationKind.Unknown -> {} // log
    else -> {} // tell the user
}
```

</multi-code>

## Socket Protection

The ENS connection must go outside the VPN tunnel.

- Android: pass a `ProtectCallback` that calls `VpnService.protect(fd)`.
- Other platforms: pass null. The library uses its built-in protector.

A failing `protect` is only logged.

<multi-code-select></multi-code-select>

<multi-code>

```go
type Protector struct{}

func (p Protector) Protect(socketFd int32) error {
    return nil
}

var protector ens.ProtectCallback = Protector{}
connection, err := ens.Connect(socketAddr, &protector, authentication, handler, config)
```

```swift
class Protector: ProtectCallback {
    func protect(socketFd: Int32) throws {}
}
```

```cs
class Protector : ProtectCallback {
    public void Protect(int socketFd) {}
}
```

```kotlin
class Protector(private val vpnService: VpnService) : ProtectCallback {
    override fun protect(socketFd: Int) {
        vpnService.protect(socketFd)
    }
}
```

</multi-code>

## Connect / Shutdown

`connect` takes the server IP and the ENS port as `ip:port`, e.g.
`185.16.207.58:993`. Hostnames are rejected with `InvalidInput`.

`connect` returns after validating its arguments and starting the background
session. It may fail synchronously because of invalid input, missing
initialization, or an internal platform/runtime setup failure. Network, TLS,
authentication, and stream failures occurring after startup are reported through
`disconnected` (see [Disconnects](#disconnects)).

`shutdown` stops the session and waits up to 5 seconds for it to finish.
Afterwards only one `disconnected("shutdown")` call follows, unless the session
had already ended. It can be called more than once, and from inside `notify`.
Dropping the `Connection` also ends the session, but `shutdown` reports errors.

<multi-code-select></multi-code-select>

<multi-code>

```go
connection, err := ens.Connect("185.16.207.58:993", nil, authentication, Handler{}, config)
defer connection.Destroy()

err = connection.Shutdown()
```

```swift
let connection = try connect(
    socketAddr: "185.16.207.58:993",
    protectCallback: nil,
    authentication: authentication,
    notificationCallback: Handler(),
    config: config)

try connection.shutdown()
```

```cs
using var connection = EnsMethods.Connect(
    "185.16.207.58:993", null, authentication, new Handler(), config);

connection.Shutdown();
```

```kotlin
val connection = connect("185.16.207.58:993", Protector(vpnService), authentication, handler, config)

connection.shutdown()
connection.close()
```

</multi-code>

## Disconnects

Transient failures - network, TLS, keep alive timeout - are retried with
backoff and only logged. `disconnected` is called when the session ends for
good:

- `shutdown` or `deinit` was called. Reason `shutdown`.
- The server rejected the authentication.
- The server closed the stream.
- The server certificate is not trusted.
- ECH bootstrap is enabled and the server gave no usable ECH configuration.
- `notify` threw.

The `reason` is free text for logs and shouldn't be parsed. libens doesn't
reconnect after `disconnected` - the app decides whether to call `connect` again.

## Errors

All throwing calls use one error type:

| Language | Type                                                                |
|----------|---------------------------------------------------------------------|
| Go       | `error`, match with `errors.Is(err, ens.ErrEnsError<Variant>)`      |
| Swift    | `EnsError.<Variant>`                                                |
| C#       | `EnsException.<Variant>`, `Error` suffix becomes `Exception`        |
| Kotlin   | `EnsException.<Variant>`, `Error` suffix becomes `Exception`        |

| Variant              | Cause                                              |
|----------------------|----------------------------------------------------|
| `InvalidInput`       | Bad argument: address, key, credentials, config.   |
| `NotInitialized`     | Called before `init` or after `deinit`.            |
| `AlreadyInitialized` | `init` called twice.                               |
| `InternalError`      | Library failure, e.g. second `set_log_callback`.   |
| `TransportError`     | Network or TLS failure.                            |
| `StatusError`        | gRPC status from the server.                       |
| `UnknownError`       | Anything else.                                     |

Reasons are censored in release builds.
