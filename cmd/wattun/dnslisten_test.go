package main

import (
	"net"
	"testing"
	"time"
)

func TestDNSServfail(t *testing.T) {
	// 12-byte minimal DNS query
	q := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // standard query, RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		0x03, 'w', 'a', 't', 0x00, // question name "wat."
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}

	sf := dnsServfail(q)
	if sf == nil {
		t.Fatal("expected non-nil servfail response")
	}
	if len(sf) != len(q) {
		t.Fatalf("servfail length = %d, want %d", len(sf), len(q))
	}
	if sf[0] != 0x12 || sf[1] != 0x34 {
		t.Errorf("ID mismatch: got %02x%02x, want 1234", sf[0], sf[1])
	}
	// flags: byte 2 = 0x81 (QR=1, RD=1), byte 3 = 0x82 (RA=1, RCODE=2)
	if sf[2] != 0x81 || sf[3] != 0x82 {
		t.Errorf("flags mismatch: got %02x%02x, want 8182", sf[2], sf[3])
	}

	// Short query (<12 bytes) returns nil
	if dnsServfail([]byte{1, 2, 3}) != nil {
		t.Error("short query should return nil")
	}
}

func TestDNSListenerServfailWhenTunnelDown(t *testing.T) {
	// Listener points to a getTun that returns nil (tunnel down)
	l, err := startDNSListener("127.0.0.1:0", func() *tunnel { return nil }, nil)
	if err != nil {
		t.Fatalf("startDNSListener failed: %v", err)
	}
	defer l.Close()

	closer := l.(*dnsListenerCloser)
	addr := closer.pc.LocalAddr().String()

	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("net.Dial failed: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	q := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}
	if _, err := client.Write(q); err != nil {
		t.Fatalf("write query failed: %v", err)
	}

	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read servfail failed: %v", err)
	}
	if n != len(q) {
		t.Fatalf("got %d bytes, want %d", n, len(q))
	}
	if buf[0] != 0xab || buf[1] != 0xcd {
		t.Errorf("ID mismatch: got %02x%02x, want abcd", buf[0], buf[1])
	}
	if buf[3]&0x0f != 2 {
		t.Errorf("expected RCODE 2 (ServFail), got %d", buf[3]&0x0f)
	}
}

func TestDNSListenerSemaphoreBoundsConcurrency(t *testing.T) {
	// Start listener pointing to a getTun that returns nil
	l, err := startDNSListener("127.0.0.1:0", func() *tunnel { return nil }, nil)
	if err != nil {
		t.Fatalf("startDNSListener failed: %v", err)
	}
	defer l.Close()

	addr := l.(*dnsListenerCloser).pc.LocalAddr().String()

	// Send 150 concurrent queries; all should complete cleanly without panicking or hanging
	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	q := []byte{
		0x99, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o', 0x00,
	}

	for i := 0; i < 50; i++ {
		if _, err := client.Write(q); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("query %d failed: %v", i, err)
		}
		if n < 12 || buf[3]&0x0f != 2 {
			t.Fatalf("expected SERVFAIL on query %d, got n=%d", i, n)
		}
	}
}

func TestDNSListenerTCP(t *testing.T) {
	l, err := startDNSListener("127.0.0.1:0", func() *tunnel { return nil }, nil)
	if err != nil {
		t.Fatalf("startDNSListener failed: %v", err)
	}
	defer l.Close()

	closer := l.(*dnsListenerCloser)
	if closer.ln == nil {
		t.Fatal("expected TCP listener to be active")
	}
	addr := closer.ln.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial tcp %s failed: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	q := []byte{
		0xfe, 0xdc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
	}

	// Write RFC 1035 TCP-framed DNS query: [2-byte length][query]
	hdr := [2]byte{byte(len(q) >> 8), byte(len(q))}
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write tcp hdr: %v", err)
	}
	if _, err := conn.Write(q); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}

	// Read 2-byte response length
	var rlenHdr [2]byte
	var rlen int
	for r := 0; r < 2; {
		n, err := conn.Read(rlenHdr[r:])
		if err != nil {
			t.Fatalf("read rlenHdr: %v", err)
		}
		r += n
	}
	rlen = int(rlenHdr[0])<<8 | int(rlenHdr[1])
	if rlen != len(q) {
		t.Fatalf("response length mismatch: got %d, want %d", rlen, len(q))
	}

	buf := make([]byte, rlen)
	for r := 0; r < rlen; {
		n, err := conn.Read(buf[r:])
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		r += n
	}

	if buf[0] != 0xfe || buf[1] != 0xdc {
		t.Errorf("ID mismatch: got %02x%02x, want fedc", buf[0], buf[1])
	}
	if buf[3]&0x0f != 2 {
		t.Errorf("expected RCODE 2 (ServFail), got %d", buf[3]&0x0f)
	}
}
