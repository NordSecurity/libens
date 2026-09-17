package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	echVersion           = 0xfe0d
	echConfigID          = 1
	kemX25519HkdfSha256  = 0x0020
	kdfHkdfSha256        = 0x0001
	aeadAes128Gcm        = 0x0001
	aeadAes256Gcm        = 0x0002
	aeadChaCha20Poly1305 = 0x0003
	echMaxNameLength     = 0

	recordHeaderLen         = 5
	recordTypeHandshake     = 22
	handshakeClientHello    = 1
	clientRandomLen         = 32
	extServerName           = 0
	extEncryptedClientHello = 0xfe0d
	sniHostName             = 0
	keyLogFileMode          = 0o600

	alpnH2       = "h2"
	listenAddr   = "127.0.0.1:0"
	certLifetime = 24 * time.Hour
	certBackdate = time.Hour
	noName       = "-"
	echOn        = "on"
	echOff       = "off"

	usage = `echstub: TLS terminator with server-side ECH for libens tests.

Listens on 127.0.0.1, terminates TLS with a fresh CA and leaf (SANs: 127.0.0.1
and the public name), then forwards plaintext to -upstream. With -ech on it
serves one X25519 ECHConfig and sends it as retry_configs when the client
offers ECH with a different key.

Line protocol on stdout, one line per event:
  ready <port> <ca_der_b64> <ech_config_list_b64|->
  handshake <ech_accepted> <sni_seen_by_go|-> <outer_sni_from_raw_hello|->

Exits on stdin EOF. Diagnostics go to stderr, -v adds per-connection detail.

Flags:
`
)

var stdout sync.Mutex

func report(format string, args ...any) {
	stdout.Lock()
	defer stdout.Unlock()
	fmt.Printf(format+"\n", args...)
}

func main() {
	upstream := flag.String("upstream", "", "plaintext upstream host:port")
	publicName := flag.String("public-name", "", "ECHConfig public_name")
	ech := flag.String("ech", echOn, "on|off")
	verbose := flag.Bool("v", false, "debug logging on stderr")
	keyLog := flag.String("keylog", "", "append TLS secrets in NSS key log format to this file")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *upstream == "" || *publicName == "" || (*ech != echOn && *ech != echOff) {
		flag.Usage()
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	caDER, leaf := makeCerts(*publicName)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{leaf},
		NextProtos:   []string{alpnH2},
		MinVersion:   tls.VersionTLS13,
	}
	if *keyLog != "" {
		file, err := os.OpenFile(*keyLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, keyLogFileMode)
		if err != nil {
			fatal("cannot open key log", err)
		}
		cfg.KeyLogWriter = file
		slog.Info("writing TLS secrets", "path", *keyLog)
	}

	echList := noName
	if *ech == echOn {
		key, config := makeECHConfig(*publicName)
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{
			Config:      config,
			PrivateKey:  key,
			SendAsRetry: true,
		}}
		echList = base64.StdEncoding.EncodeToString(echConfigList(config))
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fatal("cannot listen", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	slog.Info("listening", "port", port, "ech", *ech, "public_name", *publicName, "upstream", *upstream)
	report("ready %d %s %s", port, base64.StdEncoding.EncodeToString(caDER), echList)

	go func() {
		io.Copy(io.Discard, os.Stdin)
		slog.Info("stdin closed, exiting")
		os.Exit(0)
	}()

	var connections atomic.Uint64
	for {
		conn, err := listener.Accept()
		if err != nil {
			fatal("accept failed", err)
		}
		go serve(conn, cfg, *upstream, slog.With("conn", connections.Add(1)))
	}
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

func makeCerts(publicName string) ([]byte, tls.Certificate) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("crypto setup failed", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "echstub CA"},
		NotBefore:             now.Add(-certBackdate),
		NotAfter:              now.Add(certLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		fatal("crypto setup failed", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		fatal("crypto setup failed", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("crypto setup failed", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: publicName},
		NotBefore:    now.Add(-certBackdate),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{publicName},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		fatal("crypto setup failed", err)
	}

	return caDER, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func makeECHConfig(publicName string) ([]byte, []byte) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fatal("crypto setup failed", err)
	}
	pub := key.PublicKey().Bytes()

	var contents []byte
	contents = append(contents, echConfigID)
	contents = binary.BigEndian.AppendUint16(contents, kemX25519HkdfSha256)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	suites := []uint16{
		kdfHkdfSha256, aeadAes128Gcm,
		kdfHkdfSha256, aeadAes256Gcm,
		kdfHkdfSha256, aeadChaCha20Poly1305,
	}
	contents = binary.BigEndian.AppendUint16(contents, uint16(2*len(suites)))
	for _, s := range suites {
		contents = binary.BigEndian.AppendUint16(contents, s)
	}
	contents = append(contents, echMaxNameLength)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)

	var config []byte
	config = binary.BigEndian.AppendUint16(config, echVersion)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	return key.Bytes(), config
}

func echConfigList(config []byte) []byte {
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	return append(list, config...)
}

type recordingConn struct {
	net.Conn
	first    []byte
	complete bool
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.complete || n == 0 {
		return n, err
	}

	c.first = append(c.first, b[:n]...)
	if len(c.first) < recordHeaderLen {
		return n, err
	}

	total := recordHeaderLen + int(binary.BigEndian.Uint16(c.first[3:5]))
	if len(c.first) >= total {
		c.first = c.first[:total]
		c.complete = true
	}
	return n, err
}

func serve(conn net.Conn, base *tls.Config, upstream string, logger *slog.Logger) {
	defer conn.Close()
	logger.Debug("accepted", "remote", conn.RemoteAddr())

	recording := &recordingConn{Conn: conn}
	seen := ""
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		seen = hello.ServerName
		logger.Debug("client hello seen by go",
			"server_name", hello.ServerName,
			"alpn", hello.SupportedProtos,
			"versions", hello.SupportedVersions)
		return nil, nil
	}

	tlsConn := tls.Server(recording, cfg)
	err := tlsConn.Handshake()
	outer := parseOuterHello(recording.first)
	state := tlsConn.ConnectionState()
	logger.Debug("outer client hello",
		"bytes", len(recording.first),
		"sni", outer.sni,
		"ech_extension", outer.ech)
	logger.Debug("handshake finished",
		"err", err,
		"version", tls.VersionName(state.Version),
		"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
		"alpn", state.NegotiatedProtocol,
		"ech_accepted", state.ECHAccepted)
	report("handshake %t %s %s", state.ECHAccepted, orDash(seen), orDash(outer.sni))
	if err != nil {
		logger.Warn("handshake failed", "err", err)
		return
	}

	up, err := net.Dial("tcp", upstream)
	if err != nil {
		logger.Warn("upstream dial failed", "err", err)
		return
	}
	defer up.Close()
	logger.Debug("upstream connected", "local", up.LocalAddr())

	done := make(chan struct{}, 2)
	go func() {
		n, err := io.Copy(up, tlsConn)
		logger.Debug("client to upstream finished", "bytes", n, "err", err)
		done <- struct{}{}
	}()
	go func() {
		n, err := io.Copy(tlsConn, up)
		logger.Debug("upstream to client finished", "bytes", n, "err", err)
		done <- struct{}{}
	}()
	<-done
	logger.Debug("closing")
}

func orDash(name string) string {
	if name == "" {
		return noName
	}
	return name
}

type reader struct {
	b  []byte
	ok bool
}

func newReader(b []byte) *reader {
	return &reader{b: b, ok: true}
}

func (r *reader) take(n int) []byte {
	if !r.ok || len(r.b) < n {
		r.ok = false
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	v := r.take(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (r *reader) u16() int {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}

func (r *reader) u24() int {
	v := r.take(3)
	if v == nil {
		return 0
	}
	return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
}

func (r *reader) vec8() []byte  { return r.take(r.u8()) }
func (r *reader) vec16() []byte { return r.take(r.u16()) }
func (r *reader) vec24() []byte { return r.take(r.u24()) }

type outerHello struct {
	sni string
	ech bool
}

func parseOuterHello(record []byte) outerHello {
	var hello outerHello
	r := newReader(record)
	if r.u8() != recordTypeHandshake {
		return hello
	}
	r.take(2)
	r = newReader(r.vec16())
	if r.u8() != handshakeClientHello {
		return hello
	}
	r = newReader(r.vec24())
	r.take(2)
	r.take(clientRandomLen)
	r.vec8()
	r.vec16()
	r.vec8()

	exts := newReader(r.vec16())
	for exts.ok && len(exts.b) > 0 {
		typ := exts.u16()
		data := exts.vec16()
		switch typ {
		case extServerName:
			hello.sni = serverName(data)
		case extEncryptedClientHello:
			hello.ech = true
		}
	}
	return hello
}

func serverName(ext []byte) string {
	list := newReader(newReader(ext).vec16())
	for list.ok && len(list.b) > 0 {
		nameType := list.u8()
		name := list.vec16()
		if list.ok && nameType == sniHostName {
			return string(name)
		}
	}
	return ""
}
