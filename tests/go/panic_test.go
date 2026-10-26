package ens_test

import (
	"strings"
	"testing"

	"github.com/NordSecurity/libens/bindings/go/ens"
)

const callbackPanicReason = "callback panicked"

type panickingRecorder struct {
	*recorder
}

func (p panickingRecorder) Notify(ens.ConnectionErrorNotification) {
	panic("notify failed")
}

func TestPanicInNotify(t *testing.T) {
	server := startStub(t, nordLynxSchema)

	callback := panickingRecorder{newRecorder()}
	connection := connect(t, server, keyAuthentication(t, server.publicKey(t)), nil, callback)
	defer connection.Destroy()

	server.notify(t, serverMaintenanceCode, nil)

	reason := callback.waitDisconnect(t)
	if reason == nil || !strings.HasPrefix(*reason, callbackPanicReason) {
		t.Errorf("Expected %q, got %v", callbackPanicReason, reason)
	}
}
