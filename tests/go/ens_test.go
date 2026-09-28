package ens_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/NordSecurity/libens/bindings/go/ens"
)

const (
	appVersion            = "go-tests"
	privateKeyLen         = 32
	callbackTimeout       = 10 * time.Second
	serverMaintenanceCode = 2
	maintenanceInfo       = "planned maintenance"
	shutdownReason        = "shutdown"
	wrongPassword         = "wrong"
	authRejectionReason   = "'http://127.0.0.1:%d' rejected the authentication"
)

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

	privateKey := make([]byte, privateKeyLen)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("Cannot generate a private key: %v", err)
	}

	receiveOneNotification(t, server, ens.AuthenticationWithKeys{
		Keys: ens.Keys{
			LocalPrivateKey: privateKey,
			VpnPublicKey:    server.publicKey(t),
			Kind:            ens.KeyKindNordLynx,
		},
	})
}

func TestNotificationOverPasswordAuthentication(t *testing.T) {
	server := startStub(t, openVpnSchema)

	receiveOneNotification(t, server, ens.AuthenticationWithCredentials{
		Credentials: ens.Credentials{
			Username: server.handshake.Username,
			Password: server.handshake.Password,
			Kind:     ens.CredentialsKindOpenVpn,
		},
	})
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

	assertDisconnect(t, callback, fmt.Sprintf(authRejectionReason, server.handshake.Port))

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

	server.notify(t, serverMaintenanceCode, maintenanceInfo)

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
	if reason == nil || *reason != expected {
		t.Errorf("Expected %q, got %v", expected, reason)
	}
}
