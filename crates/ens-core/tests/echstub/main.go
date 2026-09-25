package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
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
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	echVersion            = 0xfe0d
	echConfigID           = 1
	kemX25519HkdfSha256   = 0x0020
	kemMlkem768X25519     = 0x647a
	kdfHkdfSha256         = 0x0001
	aeadAes128Gcm         = 0x0001
	aeadAes256Gcm         = 0x0002
	aeadChaCha20Poly1305  = 0x0003
	aeadExportOnly        = 0xffff
	echMaxNameLength      = 0
	echConfigLengthOffset = 2
	// config_id and half of kem_id
	truncatedKemLength = 2
	// config_id, kem_id, public_key length and one byte of public_key
	truncatedKeyLength = 6

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

	retryGood           = "good"
	retryUnusableAead   = "unusable-aead"
	retryPqKem          = "pq-kem"
	retryUnknownVersion = "unknown-version"
	retryBadPublicName  = "bad-public-name"
	retryMalformed      = "malformed"
	retryStale          = "stale"
	retryTruncatedKem   = "truncated-kem"
	retryTruncatedKey   = "truncated-key"
	badPublicName       = "not a name"
	badForever          = 0

	usage = `echstub: TLS terminator with server-side ECH for libens tests.

Listens on 127.0.0.1, terminates TLS with a fresh CA and leaf (SANs: 127.0.0.1,
-public-name and -tls-domain), then forwards plaintext to -upstream. With -ech on it
serves one X25519 ECHConfig and sends it as retry_configs when the client
offers ECH with a different key.

-retry replaces that config for the first -bad-connections connections
(0 means forever):
  unusable-aead    export-only AEAD, rustls finds no compatible suite
  pq-kem           MLKEM768-X25519 KEM, rustls HPKE has no PQ KEM
  unknown-version  version 0xfe0e, skipped by both Go and rustls
  bad-public-name  public_name is not a DNS name, rustls cannot parse the list
  malformed        corrupt length, Go aborts every ECH handshake
  stale            valid key replaced by the good one, as after key rotation
  truncated-kem    length ends inside kem_id, Go ignores it, rustls can't parse
  truncated-key    length ends inside public_key, Go ignores it, rustls can't parse

Line protocol on stdout, one line per event:
  ready <port> <ca_der_b64> <ech_config_list_b64|->
  handshake <conn_id> <ech_accepted> <sni_seen_by_go|-> <outer_sni_from_raw_hello|->

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
	tlsDomain := flag.String("tls-domain", "", "inner name the leaf certificate also covers")
	ech := flag.String("ech", echOn, "on|off")
	retry := flag.String("retry", retryGood, "good|unusable-aead|pq-kem|unknown-version|bad-public-name|malformed|stale|truncated-kem|truncated-key")
	badConnections := flag.Uint64("bad-connections", badForever, "connections served with the -retry config before switching to the good one, 0 means forever")
	verbose := flag.Bool("v", false, "debug logging on stderr")
	keyLog := flag.String("keylog", "", "append TLS secrets in NSS key log format to this file")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *upstream == "" || *publicName == "" || (*ech != echOn && *ech != echOff) || !slices.Contains(retryKinds, *retry) {
		flag.Usage()
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	caDER, leaf := makeCerts(*publicName, *tlsDomain)
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

	var keys *echKeys
	echList := noName
	if *ech == echOn {
		keys = &echKeys{
			good:           makeRetryKey(retryGood, *publicName),
			bad:            makeRetryKey(*retry, *publicName),
			badConnections: *badConnections,
		}
		echList = base64.StdEncoding.EncodeToString(echConfigList(keys.good.Config))
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fatal("cannot listen", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	slog.Info("listening", "port", port, "ech", *ech, "retry", *retry, "bad_connections", *badConnections, "public_name", *publicName, "upstream", *upstream)
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
		id := connections.Add(1)
		perConn := cfg
		if keys != nil {
			perConn = cfg.Clone()
			perConn.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{keys.forConnection(id)}
		}
		go serve(conn, perConn, *upstream, id, slog.With("conn", id))
	}
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

func makeCerts(publicName, tlsDomain string) ([]byte, tls.Certificate) {
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
	dnsNames := []string{publicName}
	if tlsDomain != "" {
		dnsNames = append(dnsNames, tlsDomain)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: publicName},
		NotBefore:    now.Add(-certBackdate),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		fatal("crypto setup failed", err)
	}

	return caDER, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

var supportedAeads = []uint16{aeadAes128Gcm, aeadAes256Gcm, aeadChaCha20Poly1305}

var retryKinds = []string{
	retryGood,
	retryUnusableAead,
	retryPqKem,
	retryUnknownVersion,
	retryBadPublicName,
	retryMalformed,
	retryStale,
	retryTruncatedKem,
	retryTruncatedKey,
}

type echKeys struct {
	good           tls.EncryptedClientHelloKey
	bad            tls.EncryptedClientHelloKey
	badConnections uint64
}

func (k *echKeys) forConnection(id uint64) tls.EncryptedClientHelloKey {
	if k.badConnections == badForever || id <= k.badConnections {
		return k.bad
	}
	return k.good
}

func makeRetryKey(kind, publicName string) tls.EncryptedClientHelloKey {
	version, kem, name, aeads := uint16(echVersion), uint16(kemX25519HkdfSha256), publicName, supportedAeads
	priv, pub := makeECHKey()
	switch kind {
	case retryUnusableAead:
		aeads = []uint16{aeadExportOnly}
	case retryPqKem:
		kem = kemMlkem768X25519
		priv, pub = makeHybridKey()
	case retryUnknownVersion:
		version = echVersion + 1
	case retryBadPublicName:
		name = badPublicName
	case retryStale:
		// Same format as the good config, but makeECHKey gave it a different
		// random key. A client still using it after the switch to the good key
		// is rejected, because the server can't decrypt its hello. This is
		// what a client sees after the server rotates its key.
	}

	config := makeECHConfig(version, kem, name, pub, aeads)
	if kind == retryMalformed {
		config[echConfigLengthOffset] = ^config[echConfigLengthOffset]
	}
	if kind == retryTruncatedKem {
		binary.BigEndian.PutUint16(config[echConfigLengthOffset:], truncatedKemLength)
	}
	if kind == retryTruncatedKey {
		binary.BigEndian.PutUint16(config[echConfigLengthOffset:], truncatedKeyLength)
	}

	return tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv,
		SendAsRetry: true,
	}
}

func makeECHKey() ([]byte, []byte) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fatal("crypto setup failed", err)
	}

	return key.Bytes(), key.PublicKey().Bytes()
}

func makeHybridKey() ([]byte, []byte) {
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		fatal("crypto setup failed", err)
	}
	priv, err := key.Bytes()
	if err != nil {
		fatal("crypto setup failed", err)
	}

	return priv, key.PublicKey().Bytes()
}

func makeECHConfig(version, kem uint16, publicName string, pub []byte, aeads []uint16) []byte {
	var contents []byte
	contents = append(contents, echConfigID)
	contents = binary.BigEndian.AppendUint16(contents, kem)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	contents = binary.BigEndian.AppendUint16(contents, uint16(4*len(aeads)))
	for _, aead := range aeads {
		contents = binary.BigEndian.AppendUint16(contents, kdfHkdfSha256)
		contents = binary.BigEndian.AppendUint16(contents, aead)
	}
	contents = append(contents, echMaxNameLength)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0)

	var config []byte
	config = binary.BigEndian.AppendUint16(config, version)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	return config
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

func serve(conn net.Conn, base *tls.Config, upstream string, id uint64, logger *slog.Logger) {
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
	report("handshake %d %t %s %s", id, state.ECHAccepted, orDash(seen), orDash(outer.sni))
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
