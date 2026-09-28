package ens_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	nordLynxSchema = "nordlynx"
	openVpnSchema  = "openvpn"
	stubEnvVar     = "ENS_STUB"
	notifyCommand  = "notification"
)

type command struct {
	Command        string `json:"command"`
	Code           int32  `json:"code"`
	AdditionalInfo string `json:"additional_info"`
}

type handshake struct {
	Port            uint16 `json:"port"`
	PublicKey       string `json:"public_key"`
	RootCertificate string `json:"root_certificate"`
	Username        string `json:"username"`
	Password        string `json:"password"`
}

type stub struct {
	handshake handshake

	stdin io.WriteCloser
}

func startStub(t *testing.T, schema string) *stub {
	t.Helper()

	cmd := exec.Command(stubPath(t), schema)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Cannot read the stub stdout: %v", err)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Cannot write to the stub stdin: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("Cannot start the stub: %v", err)
	}

	t.Cleanup(func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("The stub exited with %v", err)
		}
	})

	return &stub{handshake: readHandshake(t, stdout), stdin: stdin}
}

func (s *stub) notify(t *testing.T, code int32, additionalInfo string) {
	t.Helper()

	encoded, err := json.Marshal(command{
		Command:        notifyCommand,
		Code:           code,
		AdditionalInfo: additionalInfo,
	})
	if err != nil {
		t.Fatalf("Cannot encode the command: %v", err)
	}

	if _, err := s.stdin.Write(append(encoded, '\n')); err != nil {
		t.Fatalf("Cannot send %s: %v", encoded, err)
	}
}

func (s *stub) publicKey(t *testing.T) []byte {
	return decode(t, s.handshake.PublicKey)
}

func (s *stub) rootCertificate(t *testing.T) []byte {
	return decode(t, s.handshake.RootCertificate)
}

func readHandshake(t *testing.T, stdout io.Reader) handshake {
	t.Helper()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("The stub announced nothing: %v", err)
	}

	var announced handshake
	if err := json.Unmarshal([]byte(line), &announced); err != nil {
		t.Fatalf("Cannot parse the announcement %q: %v", line, err)
	}

	return announced
}

func stubPath(t *testing.T) string {
	t.Helper()

	if path := os.Getenv(stubEnvVar); path != "" {
		return path
	}

	target := os.Getenv("CARGO_TARGET_DIR")
	if target == "" {
		target = filepath.Join("..", "..", "target")
	}

	return filepath.Join(target, "debug", "ens-stub")
}

func decode(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("Cannot decode %q: %v", value, err)
	}

	return decoded
}
