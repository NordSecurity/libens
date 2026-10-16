package ens_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
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
	connection := connect(t, server, keyAuthentication(t, server.publicKey(t)), callback)
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

func TestLogCallback(t *testing.T) {
	select {
	case <-logs.messages:
	default:
		t.Fatal("No log message arrived")
	}
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
	}, callback)
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
	callback ens.ErrorNotificationCallback,
) *ens.Connection {
	t.Helper()

	config := ens.NewConfig()
	rootCertificate := server.rootCertificate(t)
	config.SetRootCertificateOverride(&rootCertificate)

	connection, err := ens.Connect(
		fmt.Sprintf("127.0.0.1:%d", server.handshake.Port),
		nil,
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

	connection := connect(t, server, authentication, callback)
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
