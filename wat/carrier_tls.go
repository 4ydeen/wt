package wat

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"
)

// The tls carrier is the tcp pool with every connection wrapped in TLS 1.3, so the traffic looks like HTTPS to a
// middlebox. It adds no security of its own: the session already authenticates every datagram with the PSK, which is
// why the client skips chain verification by default (pin a certificate fingerprint to also authenticate the server).

// TLSClientOptions tunes the client side of the tls carrier.
type TLSClientOptions struct {
	ServerName string // SNI sent in the ClientHello
	Verify     bool   // verify the server certificate chain (default: off, the PSK authenticates the peer)
	PinSHA256  []byte // if set, the server's leaf certificate DER must hash to this
}

func (o TLSClientOptions) config() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: o.ServerName, InsecureSkipVerify: !o.Verify}
	if len(o.PinSHA256) > 0 {
		pin := o.PinSHA256
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("tls: no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !bytes.Equal(sum[:], pin) {
				return errors.New("tls: server certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}
	return cfg
}

// NewTLSPoolClient is NewTCPPoolClient with TLS 1.3 on every connection.
func NewTLSPoolClient(peer string, conns int, o TLSClientOptions) (*TCPPoolClient, error) {
	if _, _, err := net.SplitHostPort(peer); err != nil {
		return nil, err
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: o.config()}
	return newPoolClient(func(ctx context.Context) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return d.DialContext(ctx, "tcp", peer)
	}, conns)
}

// NewTLSPoolServer listens on addr with the given certificate and key files; empty files mean a fresh in-memory
// self-signed ECDSA certificate.
func NewTLSPoolServer(addr, certFile, keyFile string) (*TCPPoolServer, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" || keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	} else {
		cert, err = SelfSignedCert()
	}
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newPoolServer(tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})), nil
}

// SelfSignedCert makes a throwaway ECDSA P-256 certificate.
func SelfSignedCert() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}
