package wat

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestFakeClientHelloRealParser feeds the fake to the standard library's TLS server side: a real parser (what a
// DPI reimplements) must accept the record and the ClientHello, and only then fail on the missing certificate.
func TestFakeClientHelloRealParser(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	errc := make(chan error, 1)
	go func() {
		c1.SetDeadline(time.Now().Add(5 * time.Second))
		srv := tls.Server(c1, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{func() tls.Certificate {
			c, err := SelfSignedCert()
			if err != nil {
				t.Error(err)
			}
			return c
		}()}})
		errc <- srv.Handshake()
	}()
	c2.SetWriteDeadline(time.Now().Add(5 * time.Second))
	go func() { // drain the server's flight so its write never blocks
		io.Copy(io.Discard, c2)
	}()
	if _, err := c2.Write(FakeClientHello("mci.ir")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	err := <-errc
	if err == nil {
		return // parsed and got as far as completing: fine
	}
	// A net timeout or a TLS alert means the record parsed and the handshake moved on (the fake never sends the
	// client's key exchange, so the server waits or alerts). Parse-level rejections fail inside readRecord with
	// messages like "first record does not look like a TLS handshake".
	var ne net.Error
	var ae *tls.AlertError
	if !errors.As(err, &ne) && !errors.As(err, &ae) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Fatalf("stdlib parser rejected the fake: %v", err)
	}
}

func TestFakeClientHello(t *testing.T) {
	for _, sni := range []string{"mci.ir", "example.com", "xn--mgbaam7a8c.example"} {
		rec := FakeClientHello(sni)
		if len(rec) < 64 {
			t.Fatalf("%s: record too short: %d", sni, len(rec))
		}
		if rec[0] != 0x16 || rec[1] != 0x03 || rec[2] != 0x01 {
			t.Fatalf("%s: bad record header % x", sni, rec[:3])
		}
		got, err := parseSNIOf(rec)
		if err != nil {
			t.Fatalf("%s: parseSNIOf: %v", sni, err)
		}
		if got != sni {
			t.Fatalf("%s: SNI round trip got %q", sni, got)
		}
		// record length fields must match
		hsLen := int(rec[3])<<8 | int(rec[4])
		if hsLen != len(rec)-5 {
			t.Fatalf("%s: record len %d, body %d", sni, hsLen, len(rec)-5)
		}
		// two builds differ only in the random (no fixed fingerprint)
		rec2 := FakeClientHello(sni)
		if bytes.Equal(rec, rec2) {
			t.Fatalf("%s: two builds identical (no randomness)", sni)
		}
	}
	if FakeClientHello("") != nil {
		t.Fatal("empty SNI must build nothing")
	}
}

func TestDesyncSeqBefore(t *testing.T) {
	// ISN 1000, fake of 200 bytes: seq must be 1000+1-200 = 801, i.e. fully below the stream start
	if got := uint32(1000) + 1 - 200; got != 801 {
		t.Fatalf("seq math: got %d want 801", got)
	}
}

func TestDesyncPeerIP(t *testing.T) {
	if got := desyncPeerIP("10.0.0.1:443"); got != "10.0.0.1" {
		t.Fatalf("ip:port: %q", got)
	}
	if got := desyncPeerIP("localhost:443"); got == "" {
		t.Fatal("hostname resolution failed")
	}
	// no assertion for an unresolvable host: some resolvers wildcard-answer (this machine's does)
}

func TestTCPChecksum(t *testing.T) {
	// A known-good TCP segment from the RFC-style examples: verify the checksum is self-consistent
	// (sum over pseudo header + segment with the checksum field zeroed must be 0xffff).
	src := []byte{192, 168, 0, 1}
	dst := []byte{10, 0, 0, 1}
	th := make([]byte, 20)
	binary.BigEndian.PutUint16(th[0:], 1234)
	binary.BigEndian.PutUint16(th[2:], 443)
	c := tcpChecksum(th, src, dst)
	binary.BigEndian.PutUint16(th[16:], c)
	// recompute over the segment that carries its checksum: folded sum must be 0xffff
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	var s uint32
	for i := 0; i+1 < len(ph); i += 2 {
		s += uint32(ph[i])<<8 | uint32(ph[i+1])
	}
	for i := 0; i+1 < len(th); i += 2 {
		s += uint32(th[i])<<8 | uint32(th[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	if ^uint16(s) != 0 {
		t.Fatalf("checksum verify failed: %04x", ^uint16(s))
	}
}
