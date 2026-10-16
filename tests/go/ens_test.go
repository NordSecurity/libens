package ens_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/NordSecurity/libens/bindings/go/ens"
)

const (
	appVersion                 = "go-tests"
	privateKeyLen              = 32
	callbackTimeout            = 10 * time.Second
	connectionLimitReachedCode = 1
	serverMaintenanceCode      = 2
	unauthenticatedCode        = 3
	supersededCode             = 4
	unsupportedCipherCode      = 5
	unknownCode                = 99
	maintenanceInfo            = "planned maintenance"
	malformedAddress           = "not-an-address"
	versionPattern             = `^v\d+\.\d+\.\d+`
	bufferSize                 = 8
	backoffInitialSeconds      = 1
	keepaliveIntervalSeconds   = 30
	bootstrapEchTimeoutSeconds = 10
	shutdownReason             = "shutdown"
	wrongPassword              = "wrong"
	authRejectionReason        = "persistent error code: 'The request does not have valid authentication credentials', message: \"Incorrect password\""
)

var logs = newLogRecorder()

type logRecorder struct {
	messages chan string
}

func newLogRecorder() *logRecorder {
	return &logRecorder{messages: make(chan string, 1)}
}

func (l *logRecorder) Log(_ ens.LogLevel, message string) {
	select {
	case l.messages <- message:
	default:
	}
}

type protector struct {
	sockets chan int32
}

func newProtector() *protector {
	return &protector{sockets: make(chan int32, 1)}
}

func (p *protector) Protect(socketFd int32) error {
	select {
	case p.sockets <- socketFd:
	default:
	}

	return nil
}

type recorder struct {
	notifications chan ens.ConnectionErrorNotification
	disconnects   chan *string
}

func newRecorder() *recorder {
	return &recorder{
		notifications: make(chan ens.ConnectionErrorNotification, 1),
		disconnects:   make(chan *string, 1),
	}
}

func (r *recorder) Notify(notification ens.ConnectionErrorNotification) {
	r.notifications <- notification
}

func (r *recorder) Disconnected(reason *string) {
	r.disconnects <- reason
}

func (r *recorder) waitNotification(t *testing.T) ens.ConnectionErrorNotification {
	t.Helper()

	select {
	case notification := <-r.notifications:
		return notification
	case <-time.After(callbackTimeout):
		t.Fatal("No notification arrived")
		return ens.ConnectionErrorNotification{}
	}
}

func (r *recorder) waitDisconnect(t *testing.T) *string {
	t.Helper()

	select {
	case reason := <-r.disconnects:
		return reason
	case <-time.After(callbackTimeout):
		t.Fatal("No disconnect arrived")
		return nil
	}
}

func TestMain(m *testing.M) {
	if err := ens.SetLogCallback(ens.LogLevelDebug, logs); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot set the log callback: %v\n", err)
		os.Exit(1)
	}

	if err := ens.Init(appVersion); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot initialize libens: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err := ens.Deinit(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot deinitialize libens: %v\n", err)
		os.Exit(1)
	}

	os.Exit(code)
}

func TestNotificationOverKeyAuthentication(t *testing.T) {
	server := startStub(t, nordLynxSchema)

	receiveOneNotification(t, server, keyAuthentication(t, server.publicKey(t)))
}

func TestNotificationOverPasswordAuthentication(t *testing.T) {
	server := startStub(t, openVpnSchema)

	receiveOneNotification(t, server, credentialsAuthentication(server, ens.CredentialsKindOpenVpn))
}

func TestNotificationOverNordWhisperAuthentication(t *testing.T) {
	server := startStub(t, nordWhisperSchema)

	receiveOneNotification(t, server, credentialsAuthentication(server, ens.CredentialsKindNordWhisper))
}

func TestNotificationKinds(t *testing.T) {
	server := startStub(t, nordLynxSchema)

	expected := []struct {
		code int32
		kind ens.ConnectionErrorNotificationKind
	}{
		{connectionLimitReachedCode, ens.ConnectionErrorNotificationKindConnectionLimitReached{}},
		{serverMaintenanceCode, ens.ConnectionErrorNotificationKindServerMaintenance{}},
		{unauthenticatedCode, ens.ConnectionErrorNotificationKindUnauthenticated{}},
		{supersededCode, ens.ConnectionErrorNotificationKindSuperseded{}},
		{unsupportedCipherCode, ens.ConnectionErrorNotificationKindUnsupportedCipher{}},
		{unknownCode, ens.ConnectionErrorNotificationKindUnknown{Kind: unknownCode}},
	}

	callback := newRecorder()
	connection := connect(t, server, keyAuthentication(t, server.publicKey(t)), nil, callback)
	defer connection.Destroy()

	for _, notification := range expected {
		server.notify(t, notification.code, nil)

		received := callback.waitNotification(t)
		if received.Kind != notification.kind {
			t.Errorf("Expected %#v, got %#v", notification.kind, received.Kind)
		}
	}
}

func TestMalformedAddress(t *testing.T) {
	_, err := ens.Connect(
		malformedAddress,
		nil,
		keyAuthentication(t, make([]byte, privateKeyLen)),
		newRecorder(),
		ens.NewConfig(),
	)
	if !errors.Is(err, ens.ErrEnsErrorInvalidInput) {
		t.Errorf("Expected an invalid input error, got %v", err)
	}
}

func TestSecondInit(t *testing.T) {
	if err := ens.Init(appVersion); !errors.Is(err, ens.ErrEnsErrorAlreadyInitialized) {
		t.Errorf("Expected an already initialized error, got %v", err)
	}
}

func TestProtectCallback(t *testing.T) {
	server := startStub(t, nordLynxSchema)

	protect := newProtector()
	connection := connect(t, server, keyAuthentication(t, server.publicKey(t)), protect, newRecorder())
	defer connection.Destroy()

	select {
	case socket := <-protect.sockets:
		if socket < 0 {
			t.Errorf("Expected a socket, got %d", socket)
		}
	case <-time.After(callbackTimeout):
		t.Fatal("No socket protected")
	}
}

func TestLogCallback(t *testing.T) {
	select {
	case <-logs.messages:
	default:
		t.Fatal("No log message arrived")
	}
}

func TestVersion(t *testing.T) {
	version := ens.GetVersion()
	if !regexp.MustCompile(versionPattern).MatchString(version) {
		t.Errorf("Expected a vX.Y.Z version, got %q", version)
	}
}

func TestMemoryUsage(t *testing.T) {
	if ens.GetMemoryUsage() == 0 {
		t.Error("Expected a non zero memory usage")
	}
}

func TestConfigSetters(t *testing.T) {
	server := startStub(t, nordLynxSchema)

	keepaliveInterval := uint32(keepaliveIntervalSeconds)

	config := ens.NewConfig()
	config.SetBufferSize(bufferSize)
	config.SetAllowOnlyPq(true)
	config.SetTlsDomain(nil)
	config.SetEnableEchBootstrap(false)
	config.SetBackoffInitial(backoffInitialSeconds)
	config.SetBackoffMaximal(nil)
	config.SetKeepaliveInterval(&keepaliveInterval)
	config.SetKeepaliveTimeout(nil)
	config.SetBootstrapEchTimeout(bootstrapEchTimeoutSeconds)

	callback := newRecorder()
	connection := connectWithConfig(t, server, keyAuthentication(t, server.publicKey(t)), nil, callback, config)
	defer connection.Destroy()

	info := maintenanceInfo
	server.notify(t, serverMaintenanceCode, &info)

	callback.waitNotification(t)
}

func TestAuthenticationRejection(t *testing.T) {
	server := startStub(t, openVpnSchema)

	callback := newRecorder()
	connection := connect(t, server, ens.AuthenticationWithCredentials{
		Credentials: ens.Credentials{
			Username: server.handshake.Username,
			Password: wrongPassword,
			Kind:     ens.CredentialsKindOpenVpn,
		},
	}, nil, callback)
	defer connection.Destroy()

	assertDisconnect(t, callback, authRejectionReason)

	if len(callback.notifications) != 0 {
		t.Errorf("A rejected client received %d notifications", len(callback.notifications))
	}
}

func connect(
	t *testing.T,
	server *stub,
	authentication ens.Authentication,
	protect ens.ProtectCallback,
	callback ens.ErrorNotificationCallback,
) *ens.Connection {
	t.Helper()

	return connectWithConfig(t, server, authentication, protect, callback, ens.NewConfig())
}

func connectWithConfig(
	t *testing.T,
	server *stub,
	authentication ens.Authentication,
	protect ens.ProtectCallback,
	callback ens.ErrorNotificationCallback,
	config *ens.Config,
) *ens.Connection {
	t.Helper()

	rootCertificate := server.rootCertificate(t)
	config.SetRootCertificateOverride(&rootCertificate)

	connection, err := ens.Connect(
		fmt.Sprintf("127.0.0.1:%d", server.handshake.Port),
		optional(protect),
		authentication,
		callback,
		config,
	)
	if err != nil {
		t.Fatalf("Cannot connect: %v", err)
	}

	return connection
}

func receiveOneNotification(t *testing.T, server *stub, authentication ens.Authentication) {
	t.Helper()

	callback := newRecorder()

	connection := connect(t, server, authentication, nil, callback)
	defer connection.Destroy()

	info := maintenanceInfo
	server.notify(t, serverMaintenanceCode, &info)

	notification := callback.waitNotification(t)
	if _, ok := notification.Kind.(ens.ConnectionErrorNotificationKindServerMaintenance); !ok {
		t.Errorf("Expected a maintenance notification, got %#v", notification.Kind)
	}
	if notification.AdditionalInfo == nil || *notification.AdditionalInfo != maintenanceInfo {
		t.Errorf("Expected %q, got %v", maintenanceInfo, notification.AdditionalInfo)
	}

	if err := connection.Shutdown(); err != nil {
		t.Fatalf("Cannot shut the connection down: %v", err)
	}

	assertDisconnect(t, callback, shutdownReason)
}

func assertDisconnect(t *testing.T, callback *recorder, expected string) {
	t.Helper()

	reason := callback.waitDisconnect(t)
	if reason == nil {
		t.Errorf("Expected %q, got no reason", expected)
		return
	}

	if *reason != expected {
		t.Errorf("Expected %q, got %q", expected, *reason)
	}
}

func keyAuthentication(t *testing.T, vpnPublicKey []byte) ens.Authentication {
	t.Helper()

	privateKey := make([]byte, privateKeyLen)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("Cannot generate a private key: %v", err)
	}

	return ens.AuthenticationWithKeys{
		Keys: ens.Keys{
			LocalPrivateKey: privateKey,
			VpnPublicKey:    vpnPublicKey,
			Kind:            ens.KeyKindNordLynx,
		},
	}
}

func credentialsAuthentication(server *stub, kind ens.CredentialsKind) ens.Authentication {
	return ens.AuthenticationWithCredentials{
		Credentials: ens.Credentials{
			Username: server.handshake.Username,
			Password: server.handshake.Password,
			Kind:     kind,
		},
	}
}

func optional(protect ens.ProtectCallback) *ens.ProtectCallback {
	if protect == nil {
		return nil
	}

	return &protect
}
