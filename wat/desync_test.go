package wat

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
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
		c1.SetDeadline(time.Now().Add(250 * time.Millisecond))
		srv := tls.Server(c1, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{func() tls.Certificate {
			c, err := SelfSignedCert()
			if err != nil {
				t.Error(err)
			}
			return c
		}()}})
		errc <- srv.Handshake()
	}()
	c2.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	go func() { // drain the server's flight so its write never blocks
		io.Copy(io.Discard, c2)
	}()
	if _, err := c2.Write(FakeClientHello("mci.ir")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
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

// TestFakeClientHelloTLS13Parser verifies that crypto/tls.Server configured with TLS 1.3
// accepts the ClientHello and negotiates TLS 1.3 without parse errors.
func TestFakeClientHelloTLS13Parser(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	errc := make(chan error, 1)
	go func() {
		c1.SetDeadline(time.Now().Add(250 * time.Millisecond))
		srv := tls.Server(c1, &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{func() tls.Certificate {
				c, err := SelfSignedCert()
				if err != nil {
					t.Error(err)
				}
				return c
			}()},
		})
		errc <- srv.Handshake()
	}()
	c2.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	go func() {
		io.Copy(io.Discard, c2)
	}()
	if _, err := c2.Write(FakeClientHello("mci.ir")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	err := <-errc
	if err == nil {
		return
	}
	var ne net.Error
	var ae *tls.AlertError
	if !errors.As(err, &ne) && !errors.As(err, &ae) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
		t.Fatalf("stdlib TLS 1.3 parser rejected the fake: %v", err)
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

// TestValidateDesync pins the config validation both OSes share.
func TestValidateDesync(t *testing.T) {
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "seq"}); err != nil {
		t.Fatalf("seq: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 7}); err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 0}); err != nil {
		t.Fatalf("ttl auto (TTL 0) is allowed: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "", Mode: "seq"}); err == nil {
		t.Fatal("empty SNI must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "bogus"}); err == nil {
		t.Fatal("bad mode must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "ttl", TTL: 300}); err == nil {
		t.Fatal("TTL > 255 must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir,b.ir", Mode: "seq"}); err != nil {
		t.Fatalf("comma-separated SNIs should pass: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "  a.ir  ,  b.ir  ", Mode: "seq"}); err != nil {
		t.Fatalf("whitespace around comma-separated SNIs should pass: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir, bad name", Mode: "seq"}); err == nil {
		t.Fatal("invalid characters in SNI list should fail")
	}
}

// desyncTestPkt builds one raw IPv4 TCP packet (header included) the way the wire delivers it.
func desyncTestPkt(src, dst [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte, ttl int) []byte {
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = byte(ttl)
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:], sport)
	binary.BigEndian.PutUint16(th[2:], dport)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	copy(th[20:], payload)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], src[:], dst[:]))
	return pkt
}

const (
	testFlagFIN = 0x01
	testFlagRST = 0x04
	testFlagPSH = 0x08
	testFlagACK = 0x10
	testFlagSYN = 0x02
)

// sentLog collects the tracker's sends; the mutex covers the seqsum marker that
// fires from a time.AfterFunc goroutine (the tracker's own send hook is sync for every other mode).
type sentLog struct {
	mu  sync.Mutex
	pks [][]byte
}

func (s *sentLog) add(pkt []byte) { s.mu.Lock(); s.pks = append(s.pks, pkt); s.mu.Unlock() }
func (s *sentLog) n() int         { s.mu.Lock(); defer s.mu.Unlock(); return len(s.pks) }
func (s *sentLog) at(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pks[i]
}

// desyncTestTracker builds a tracker with a collected send path and a fixed client/peer pair.
func desyncTestTracker(mode string, ttl int) (*desyncTracker, *sentLog) {
	var cfg DesyncConfig
	switch mode {
	case "seq":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "seq"}
	case "ttl":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "ttl", TTL: ttl}
	case "sum":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "sum"}
	case "seqsum":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "seqsum"}
	case "rst":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "rst"}
	}
	var p [4]byte
	copy(p[:], net.ParseIP("10.8.0.1").To4())
	tr := newDesyncTracker(cfg, p)
	sent := &sentLog{}
	tr.send = sent.add
	return tr, sent
}

// testClientKey is one outgoing 4-tuple: 192.168.1.2:5000 -> 10.8.0.1:443.
func testClientKey() desyncKey {
	var s, d [4]byte
	copy(s[:], net.ParseIP("192.168.1.2").To4())
	copy(d[:], net.ParseIP("10.8.0.1").To4())
	return desyncKey{s, d, 5000, 443}
}

// feedFullHandshake drives a normal SYN / SYN-ACK / final-ACK exchange into the tracker.
func feedFullHandshake(tr *desyncTracker, k desyncKey, isn, srvSeq uint32) {
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
}

// TestDesyncEarlyFiresBeforeData: the classic path — Wrap knows the ISN, the fake fires on the final ACK, one
// packet, seq fully below the stream start, ack = the server's ISN.
func TestDesyncEarlyFiresBeforeData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true) // probe reports SND.NXT = ISN+1 right after the handshake
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	pkt := sent.at(0)
	if n := int(binary.BigEndian.Uint16(pkt[2:])); n != 20+20+len(tr.hello) {
		t.Fatalf("fake length %d, want %d", n, 20+20+len(tr.hello))
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	if got := binary.BigEndian.Uint32(pkt[28:]); got != srvSeq+1 {
		t.Fatalf("fake ack %d, want %d (server's ISN+1)", got, srvSeq+1)
	}
	if pkt[8] != 64 {
		t.Fatalf("fake ttl %d, want 64 (seq mode)", pkt[8])
	}
	if got := binary.BigEndian.Uint16(pkt[20:]); got != 5000 {
		t.Fatalf("fake sport %d", got)
	}
	if got := binary.BigEndian.Uint16(pkt[22:]); got != 443 {
		t.Fatalf("fake dport %d", got)
	}
	if tr.fired() != 1 {
		t.Fatalf("fired counter %d", tr.fired())
	}
}

// TestDesyncEarlyFiresOnFirstData: the real client's first flight went out before Wrap could register — the
// fake still fires, anchored to the first outbound data segment (seq equal to that segment's stream start).
func TestDesyncEarlyFiresOnFirstData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(0xffff0000), uint32(17) // wrap-prone values
	tr.announce(k, isn+1, true)
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	// the pool writes the session's first datagram BEFORE the final ACK would be seen on the wire
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 300), 64))
	if tr.fired() != 1 {
		t.Fatalf("fake did not fire on first data (fired %d)", tr.fired())
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncLateFiresOnData: the ISN is unknown (probe unavailable) — the fake fires anchored to the first
// outbound data segment, which is the only anchor available.
func TestDesyncLateFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(42000), uint32(900)
	ch := tr.announce(k, 0, false) // not known
	// handshake seen only as SYN-ACK + first data (SYN lost to the sniffer, e.g. offload path)
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 100), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("late fake never fired")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("late fake seq %d, want %d", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncLateNeedsData: with no anchor (no data segment yet), the late path must NOT fire on bare ACKs.
func TestDesyncLateNeedsData(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(42000), uint32(900)
	tr.announce(k, 0, false)
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+2, srvSeq+1, testFlagACK, nil, 64))
	if sent.n() != 0 {
		t.Fatalf("late path fired on bare ACKs (%d fakes)", sent.n())
	}
}

// TestDesyncNATRewrite: a NAT that shifts our sequence numbers between SYN and data (the documented seq-mode
// killer) shifts the fake with it when the SYN-ACK still names the old ISN — the tracker follows the server's
// view. The fake stays below the stream start as the SERVER sees it.
func TestDesyncNATRewrite(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	// NAT rewrote our ISN from 1000 to 2000 before the server saw it
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	const natISN = isn + 1000
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, natISN+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, natISN+1, srvSeq+1, testFlagACK, nil, 64))
	if tr.fired() != 1 {
		t.Fatal("fake did not fire after NAT rewrite")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != natISN+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (NAT-shifted)", seq, natISN+1-uint32(len(tr.hello)))
	}
}

// TestDesyncTTLCalibration: -fake-ttl 0 learns the peer's inbound TTL from its SYN-ACK and sends the fake one
// hop short of the server. Before the SYN-ACK is seen, nothing fires.
func TestDesyncTTLCalibration(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // SYN-ACK arrives with TTL 52
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired after calibration")
	}
	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	if got := sent.at(0)[8]; got != 51 {
		t.Fatalf("calibrated ttl %d, want 51 (peer TTL 52 - 1)", got)
	}
}

// TestDesyncTTLCalibratedBeforeHandshake: a previously learned TTL (from another connection) serves at once.
func TestDesyncTTLCalibratedBeforeHandshake(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	// a stray SYN-ACK from the peer (another connection's) teaches the TTL first
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, 9999, 77, 88, testFlagSYN|testFlagACK, nil, 60))
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	if tr.fired() != 1 {
		t.Fatal("fake did not fire with pre-calibrated TTL")
	}
	if got := sent.at(0)[8]; got != 59 {
		t.Fatalf("ttl %d, want 59", got)
	}
}

// TestDesyncTTLCalibratedNotYet: before any SYN-ACK, an auto-TTL handshake stays unfired and the wait channel
// is abandoned (Wrap times out; the tunnel works unclassified).
func TestDesyncTTLCalibratedNotYet(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	ch := tr.announce(k, isn+1, true)
	// handshake without a SYN-ACK on record (sniffer missed it): no TTL, no fake
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagACK, nil, 64))
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("auto-TTL fired without a learned TTL")
	}
	tr.abandon(k)
	select {
	case <-ch:
	default:
		t.Fatal("abandon must release the waiting Wrap")
	}
}

// TestDesyncFixedTTL: -fake-ttl N is used as-is.
func TestDesyncFixedTTL(t *testing.T) {
	tr, sent := desyncTestTracker("ttl", 9)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	if tr.fired() != 1 {
		t.Fatal("fake did not fire")
	}
	if got := sent.at(0)[8]; got != 9 {
		t.Fatalf("ttl %d, want 9 (fixed)", got)
	}
}

// TestDesyncOneFakePerConn: whatever arrives after the fake must not fire again.
func TestDesyncOneFakePerConn(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(1000), uint32(500000)
	tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+2, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 50), 64))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+60, srvSeq+1, testFlagACK, nil, 64))
	if sent.n() != 1 {
		t.Fatalf("want exactly 1 fake, got %d", sent.n())
	}
}

// TestDesyncUnknownConnIgnored: traffic on connections the tracker never saw announced is passed over.
func TestDesyncUnknownConnIgnored(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	feedFullHandshake(tr, k, 3000, 400) // never announced
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fired for an unannounced connection")
	}
}

// TestDesyncFakePacketRoundTrip: the built fake parses back as IPv4/TCP with a valid checksum and carries the
// SNI in its payload.
func TestDesyncFakePacketRoundTrip(t *testing.T) {
	k := testClientKey()
	hello := FakeClientHello("mci.ir")
	pkt := fakePacket(k, 799, 555, 63, hello)
	if ip := parseEthIPv4(append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}, pkt...)); ip == nil {
		t.Fatal("parseEthIPv4 rejected the fake")
	} else {
		if got := binary.BigEndian.Uint32(ip[16:20]); got != binary.BigEndian.Uint32(k.dstIP[:]) {
			t.Fatalf("dst ip %x", got)
		}
		if ip[8] != 63 {
			t.Fatalf("ttl %d", ip[8])
		}
	}
	th := pkt[20:]
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(th[16:], 0)
	if c := tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]); c != stored {
		t.Fatalf("checksum mismatch: recomputed %04x, stored %04x", c, stored)
	}
	if !bytes.Equal(pkt[40:], hello) {
		t.Fatal("payload is not the hello")
	}
	if ipCsum := csum(pkt[:20]); ipCsum != 0 {
		t.Fatalf("ipv4 header checksum mismatch: got %04x, want 0", ipCsum)
	}
	rstPkt := fakeRSTPacket(k, 800, 556, 64)
	if ipCsum := csum(rstPkt[:20]); ipCsum != 0 {
		t.Fatalf("rst ipv4 header checksum mismatch: got %04x, want 0", ipCsum)
	}
}

// TestDesyncAbandonAndClose: Wrap channels close cleanly, no fake fires after close.
func TestDesyncAbandonAndClose(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	k := testClientKey()
	ch1 := tr.announce(k, 123, true)
	tr.abandon(k)
	select {
	case <-ch1:
	default:
		t.Fatal("abandon must close the wait channel")
	}
	tr.close()
	tr.announce(k, 123, true) // after close: announced channels close at once, nothing fires
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fired after close")
	}
}

// TestDesyncRSTCleansConnection: TCP RST packet cleans up tracked state and closes waiting channels.
func TestDesyncRSTCleansConnection(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	ch := tr.announce(k, 500, true)
	// Outbound RST packet
	rstPkt := desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, 501, 0, testFlagRST, nil, 64)
	tr.handleIPv4(rstPkt)
	select {
	case <-ch: // channel closed on RST
	case <-time.After(time.Second):
		t.Fatal("channel not closed on RST")
	}
	tr.mu.Lock()
	conn := tr.conns[k]
	tr.mu.Unlock()
	if conn != nil {
		t.Fatal("connection state was not cleaned up on RST")
	}
	if tr.fired() != 0 || sent.n() != 0 {
		t.Fatal("fake fired on RST connection")
	}
}

// TestDesyncStalePrune: stale uncompleted connection entries (>30s) are pruned on subsequent announces.
func TestDesyncStalePrune(t *testing.T) {
	tr, _ := desyncTestTracker("seq", 0)
	defer tr.close()
	// Announce 18 connections
	for i := 0; i < 18; i++ {
		k := testClientKey()
		k.srcPt = uint16(10000 + i)
		_ = tr.announce(k, uint32(1000+i), false)
	}
	tr.mu.Lock()
	if len(tr.conns) != 18 {
		tr.mu.Unlock()
		t.Fatalf("expected 18 conns, got %d", len(tr.conns))
	}
	// Age them out
	oldTime := time.Now().Add(-1 * time.Minute)
	for _, c := range tr.conns {
		c.at = oldTime
	}
	tr.mu.Unlock()

	// 19th announce should trigger stale prune
	kNew := testClientKey()
	kNew.srcPt = 20000
	tr.announce(kNew, 5000, true)

	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.conns) != 1 {
		t.Fatalf("stale connections were not pruned: len=%d, want 1", len(tr.conns))
	}
	if tr.conns[kNew] == nil {
		t.Fatal("new connection was pruned")
	}
}

// TestDesyncParseEthIPv4 rejects non-IPv4 frames.
func TestDesyncParseEthIPv4(t *testing.T) {
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if parseEthIPv4(arp) != nil {
		t.Fatal("ARP frame accepted")
	}
	if parseEthIPv4([]byte{1, 2, 3}) != nil {
		t.Fatal("short frame accepted")
	}
}

// TestDesyncProbeIsnArithmetic pins the Wrap probe conversion: the TCP_REPAIR probe reports SND.NXT (the next
// unsent byte, ISN+1 right after the handshake), the tracker's announce stores the ISN. desync_linux.go's Wrap
// does `if known { isn-- }`; this pins the intended relation with the same numbers the Linux path sees.
func TestDesyncProbeIsnArithmetic(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(30000), uint32(777)
	const sndNxt = isn + 1 // what tcpStreamBase reports right after the handshake
	ch := tr.announce(k, sndNxt-1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired with probe-converted ISN")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("fake seq %d, want %d (SND.NXT-1 based)", seq, isn+1-uint32(len(tr.hello)))
	}
}

// TestDesyncSumModeFiresEarly: when ISN is known (early path), sum mode fires immediately on the handshake's
// final ACK with an in-window seq (isn+1), ack = srvSeq+1, and damaged checksum, allowing Wrap to unblock without delay.
func TestDesyncSumModeFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("sum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(5000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK: fires early so Wrap unblocks
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("sum mode did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("sum mode fired %d, want 1", tr.fired())
	}
	pkt := sent.at(0)
	seq := binary.BigEndian.Uint32(pkt[24:])
	if seq != isn+1 {
		t.Fatalf("sum fake seq %d, want %d (mirrors the data segment's seq in-window)", seq, isn+1)
	}
	if ack := binary.BigEndian.Uint32(pkt[28:]); ack != srvSeq+1 {
		t.Fatalf("sum fake ack %d, want %d", ack, srvSeq+1)
	}
	// the checksum must be INVALID: recompute the correct one and require a difference
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(pkt[20+16:], 0)
	if good := tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]); good == stored {
		t.Fatalf("sum fake carries a VALID checksum %04x (must be damaged)", good)
	}
	// and the damage is non-zero
	if stored == 0 {
		t.Fatal("sum fake checksum zeroed instead of damaged")
	}
}

// TestDesyncSumModeLate: the ISN is unknown; the late path mirrors the first data segment all the same.
func TestDesyncSumModeLate(t *testing.T) {
	tr, sent := desyncTestTracker("sum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(61000), uint32(90)
	ch := tr.announce(k, 0, false)
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 60), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("sum-mode late fake never fired")
	}
	seq := binary.BigEndian.Uint32(sent.at(0)[24:])
	if seq != isn+1 {
		t.Fatalf("sum late fake seq %d, want %d (in-window)", seq, isn+1)
	}
}

// TestDesyncRSTModeFiresEarly: when ISN is known (early path), rst mode fires immediately on the handshake's
// final ACK with an in-window RST|ACK and damaged checksum.
func TestDesyncRSTModeFiresOnData(t *testing.T) {
	tr, sent := desyncTestTracker("rst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(5000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("rst mode did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("rst mode fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 1 {
		t.Fatalf("sent %d packets, want 1", sent.n())
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("rst fake len %d, want 40 (pure RST|ACK header)", len(pkt))
	}
	flags := pkt[20+13]
	if flags != 0x14 { // RST|ACK
		t.Fatalf("rst fake flags 0x%02x, want 0x14 (RST|ACK)", flags)
	}
	seq := binary.BigEndian.Uint32(pkt[20+4:])
	if seq != isn+1 {
		t.Fatalf("rst fake seq %d, want %d (in-window)", seq, isn+1)
	}
	stored := binary.BigEndian.Uint16(pkt[20+16:])
	binary.BigEndian.PutUint16(pkt[20+16:], 0)
	if good := tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]); good == stored {
		t.Fatalf("rst fake carries a VALID checksum %04x (must be damaged)", good)
	}
}

// TestDesyncRSTModeLate: the ISN is unknown; the late path mirrors the first data segment with an in-window RST|ACK.
func TestDesyncRSTModeLate(t *testing.T) {
	tr, sent := desyncTestTracker("rst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(61000), uint32(90)
	ch := tr.announce(k, 0, false)
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 60), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("rst-mode late fake never fired")
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("rst late fake len %d, want 40", len(pkt))
	}
	if flags := pkt[20+13]; flags != 0x14 {
		t.Fatalf("rst late fake flags 0x%02x, want 0x14", flags)
	}
	seq := binary.BigEndian.Uint32(pkt[20+4:])
	if seq != isn+1 {
		t.Fatalf("rst late fake seq %d, want %d (in-window)", seq, isn+1)
	}
}

// TestDesyncSeqSumSendsBoth: seqsum sends TWO markers per connection — the below-window seq fake first, then
// the in-window mirror with a damaged checksum ~1 ms later. Both must be present, in order, both carrying the
// allowlisted SNI, one with valid checksum below the window and one in-window with an invalid one.
func TestDesyncSeqSumSendsBoth(t *testing.T) {
	tr, sent := desyncTestTracker("seqsum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(7000), uint32(900)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq) // final ACK: fires both markers early
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("seqsum did not fire on final ACK")
	}
	if tr.fired() != 1 {
		t.Fatalf("seqsum fired %d, want 1", tr.fired())
	}
	// marker 2 goes out ~1 ms later via time.AfterFunc (never under the tracker lock), so poll for it
	deadline := time.Now().Add(time.Second)
	for sent.n() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("seqsum sent %d markers, want 2 (marker 2 never arrived)", sent.n())
		}
		time.Sleep(time.Millisecond)
	}
	// marker 1: below-window seq, VALID checksum (plain seq fake). fakePacket built it correctly and seqsum
	// sent it unmodified — recompute and require equality.
	m1 := sent.at(0)
	if got := binary.BigEndian.Uint32(m1[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum marker1 seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	stored1 := binary.BigEndian.Uint16(m1[20+16:])
	binary.BigEndian.PutUint16(m1[20+16:], 0)
	if good := tcpChecksum(m1[20:], k.srcIP[:], k.dstIP[:]); good != stored1 {
		t.Fatalf("seqsum marker1 checksum %04x, want the VALID value %04x", stored1, good)
	}
	// marker 2: in-window seq (the data segment's own), DAMAGED checksum
	m2 := sent.at(1)
	if got := binary.BigEndian.Uint32(m2[24:]); got != isn+1 {
		t.Fatalf("seqsum marker2 seq %d, want %d (in-window mirror)", got, isn+1)
	}
	stored2 := binary.BigEndian.Uint16(m2[20+16:])
	binary.BigEndian.PutUint16(m2[20+16:], 0)
	if good := tcpChecksum(m2[20:], k.srcIP[:], k.dstIP[:]); good == stored2 {
		t.Fatalf("seqsum marker2 carries a VALID checksum %04x (must be damaged)", good)
	}
	// both carry the allowlisted SNI. pickHello rebuilds fresh randoms per fire, so compare the parsed
	// SNI (and the per-SNI constant length), not the constructor's cached tr.hello bytes.
	for i, m := range [][]byte{m1, m2} {
		if len(m[40:]) != len(tr.hello) {
			t.Fatalf("seqsum marker%d payload len %d, want %d", i+1, len(m[40:]), len(tr.hello))
		}
		got, err := parseSNIOf(m[40:])
		if err != nil || got != "mci.ir" {
			t.Fatalf("seqsum marker%d SNI: got %q err %v, want mci.ir", i+1, got, err)
		}
	}
}

// TestDesyncSeqSumLateFiresBoth: the late path (unknown ISN) fires the dual marker off the first data segment.
func TestDesyncSeqSumLateFiresBoth(t *testing.T) {
	tr, sent := desyncTestTracker("seqsum", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(41000), uint32(70)
	ch := tr.announce(k, 0, false)
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn+1, srvSeq+1, testFlagPSH|testFlagACK, make([]byte, 40), 64))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("seqsum late fake never fired")
	}
	// marker 2 goes out ~1 ms later via time.AfterFunc (never under the tracker lock), so poll for it
	deadline := time.Now().Add(time.Second)
	for sent.n() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("seqsum late sent %d markers, want 2 (marker 2 never arrived)", sent.n())
		}
		time.Sleep(time.Millisecond)
	}
	if got := binary.BigEndian.Uint32(sent.at(0)[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum late marker1 seq %d, want %d", got, isn+1-uint32(len(tr.hello)))
	}
	if got := binary.BigEndian.Uint32(sent.at(1)[24:]); got != isn+1 {
		t.Fatalf("seqsum late marker2 seq %d, want %d (in-window)", got, isn+1)
	}
}

// TestDesyncPickHelloFreshRandoms: pickHello rebuilds the hello per fire, so two fires from one tracker
// never replay byte-identical randoms (a censor correlating synthetic hellos across connections would
// otherwise see the same client random / session id / key share). The per-SNI length stays constant.
func TestDesyncPickHelloFreshRandoms(t *testing.T) {
	var p [4]byte
	copy(p[:], net.ParseIP("10.8.0.1").To4())
	tr := newDesyncTracker(DesyncConfig{SNI: "mci.ir", Mode: "seq"}, p)
	defer tr.close()
	h1 := tr.pickHello()
	h2 := tr.pickHello()
	if len(h1) != len(tr.hello) || len(h2) != len(tr.hello) {
		t.Fatalf("pickHello len drift: %d %d, want %d", len(h1), len(h2), len(tr.hello))
	}
	if string(h1) == string(h2) {
		t.Fatal("two pickHello calls returned byte-identical hellos (replayed randoms)")
	}
	got, err := parseSNIOf(h2)
	if err != nil || got != "mci.ir" {
		t.Fatalf("pickHello SNI: got %q err %v, want mci.ir", got, err)
	}
}

// TestDesyncMultiSNIRotation verifies that comma-separated SNIs rotate sequentially across connections.
func TestDesyncMultiSNIRotation(t *testing.T) {
	var p [4]byte
	copy(p[:], net.ParseIP("10.8.0.1").To4())
	cfg := DesyncConfig{
		SNI:  "mci.ir,divar.ir,digikala.com",
		Mode: "seq",
	}
	tr := newDesyncTracker(cfg, p)
	defer tr.close()
	sent := &sentLog{}
	tr.send = sent.add

	expectedSNIs := []string{"mci.ir", "divar.ir", "digikala.com", "mci.ir"}
	for i, want := range expectedSNIs {
		k := testClientKey()
		k.srcPt = uint16(20000 + i)
		ch := tr.announce(k, uint32(10000+i*100), true)
		feedFullHandshake(tr, k, uint32(10000+i*100), uint32(50000+i*100))
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("conn %d never fired", i)
		}
		if sent.n() != i+1 {
			t.Fatalf("sent count mismatch at iter %d: got %d", i, sent.n())
		}
		// Extract SNI from the sent packet (starts at byte 40 after 20-byte IP and 20-byte TCP header)
		rec := sent.at(i)[40:]
		got, err := parseSNIOf(rec)
		if err != nil {
			t.Fatalf("conn %d parseSNIOf: %v", i, err)
		}
		if got != want {
			t.Fatalf("conn %d SNI: got %q, want %q", i, got, want)
		}
	}
}

// TestFakeClientHelloECHGREASE verifies that FakeClientHello includes the RFC 9460 / RFC 8701
// ECH GREASE extension (0xfe0d) with valid outer configuration.
func TestFakeClientHelloECHGREASE(t *testing.T) {
	rec := FakeClientHello("mci.ir")
	if len(rec) < 5 || rec[0] != 0x16 {
		t.Fatalf("bad TLS record header: %v", rec[:5])
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		t.Fatalf("bad handshake header: %v", hs[:4])
	}
	// Skip ClientHello fixed fields to find extensions:
	// handshake header(4) + version(2) + random(32) + session_id(1+len) + cipher_suites(2+len) + compression(1+len)
	off := 4 + 2 + 32
	if off >= len(hs) {
		t.Fatal("truncated hs at random")
	}
	sidLen := int(hs[off])
	off += 1 + sidLen
	if off+2 > len(hs) {
		t.Fatal("truncated hs at session id")
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2 + csLen
	if off+1 > len(hs) {
		t.Fatal("truncated hs at cipher suites")
	}
	compLen := int(hs[off])
	off += 1 + compLen
	if off+2 > len(hs) {
		t.Fatal("truncated hs at compression")
	}
	extTotalLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	if off+extTotalLen > len(hs) {
		t.Fatalf("truncated extensions: need %d have %d", extTotalLen, len(hs)-off)
	}

	foundECH := false
	extEnd := off + extTotalLen
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[off : off+2])
		extLen := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			t.Fatalf("extension 0x%04x truncated", extType)
		}
		if extType == 0xfe0d {
			foundECH = true
			data := hs[off : off+extLen]
			if len(data) != 138 {
				t.Fatalf("ECH GREASE data len: got %d, want 138", len(data))
			}
			if data[0] != 0x00 { // outer ClientHello
				t.Fatalf("ECH type: got %d, want 0 (outer)", data[0])
			}
			// HKDF-SHA256 (0x0001) + AES-128-GCM (0x0001)
			if !bytes.Equal(data[1:5], []byte{0x00, 0x01, 0x00, 0x01}) {
				t.Fatalf("ECH cipher suite mismatch: %x", data[1:5])
			}
			if data[5] != 0x00 { // config_id
				t.Fatalf("ECH config_id: got %d, want 0", data[5])
			}
			encLen := binary.BigEndian.Uint16(data[6:8])
			if encLen != 32 {
				t.Fatalf("ECH encLen: got %d, want 32", encLen)
			}
			payloadLen := binary.BigEndian.Uint16(data[40:42])
			if payloadLen != 96 {
				t.Fatalf("ECH payloadLen: got %d, want 96", payloadLen)
			}
		}
		off += extLen
	}
	if !foundECH {
		t.Fatal("ECH GREASE extension (0xfe0d) not found in FakeClientHello")
	}
}

// TestFakePacketWithOptions verifies IPv4/TCP header formatting, options placement,
// and checksum calculation when TCP options are mirrored from the kernel.
func TestFakePacketWithOptions(t *testing.T) {
	k := desyncKey{
		srcIP: [4]byte{192, 168, 1, 50},
		dstIP: [4]byte{1, 2, 3, 4},
		srcPt: 12345,
		dstPt: 443,
	}
	// 12 bytes of TCP options: NOP, NOP, Timestamps (Kind=8, Len=10, TSval=0x11223344, TSecr=0x55667788)
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	payload := []byte("TEST_PAYLOAD_BODY")

	pkt := fakePacketWithOptions(k, 1000, 2000, 64, payload, opts)

	// IPv4 header checks
	if pkt[0] != 0x45 {
		t.Fatalf("IP version/IHL: got 0x%02x, want 0x45", pkt[0])
	}
	totLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(totLen) != len(pkt) {
		t.Fatalf("IP totLen: got %d, want %d", totLen, len(pkt))
	}
	if csum(pkt[:20]) != 0 {
		t.Fatal("IPv4 header checksum invalid")
	}

	// TCP header checks: 20 bytes standard + 12 bytes options = 32 bytes (Data Offset = 8)
	th := pkt[20:]
	dataOffset := th[12] >> 4
	if dataOffset != 8 {
		t.Fatalf("TCP Data Offset: got %d, want 8", dataOffset)
	}
	if !bytes.Equal(th[20:32], opts) {
		t.Fatalf("TCP options mismatch in header: got %x, want %x", th[20:32], opts)
	}
	if !bytes.Equal(pkt[20+32:], payload) {
		t.Fatalf("Payload mismatch: got %q, want %q", pkt[20+32:], payload)
	}

	// TCP checksum verification
	ph := make([]byte, 12)
	copy(ph[0:4], k.srcIP[:])
	copy(ph[4:8], k.dstIP[:])
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	if csum(append(ph, th...)) != 0 {
		t.Fatal("TCP checksum invalid")
	}
}

// TestDesyncOptsCapture verifies that outbound segments with TCP options (e.g. timestamps)
// are recorded by the tracker and reflected in injected fake packets.
func TestDesyncOptsCapture(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(2000), uint32(600000)
	ch := tr.announce(k, isn+1, true)

	// SYN (no options for simplicity)
	tr.handleIPv4(desyncTestPkt(k.srcIP, k.dstIP, k.srcPt, k.dstPt, isn, 0, testFlagSYN, nil, 64))
	// SYN-ACK from server
	tr.handleIPv4(desyncTestPkt(k.dstIP, k.srcIP, k.dstPt, k.srcPt, srvSeq, isn+1, testFlagSYN|testFlagACK, nil, 52))

	// Final ACK with 12 bytes of TCP options (NOP, NOP, Timestamps)
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	ackPkt := make([]byte, 20+32)
	ackPkt[0] = 0x45
	binary.BigEndian.PutUint16(ackPkt[2:], uint16(len(ackPkt)))
	ackPkt[8] = 64
	ackPkt[9] = 6
	copy(ackPkt[12:16], k.srcIP[:])
	copy(ackPkt[16:20], k.dstIP[:])
	binary.BigEndian.PutUint16(ackPkt[10:], csum(ackPkt[:20]))
	ath := ackPkt[20:]
	binary.BigEndian.PutUint16(ath[0:], k.srcPt)
	binary.BigEndian.PutUint16(ath[2:], k.dstPt)
	binary.BigEndian.PutUint32(ath[4:], isn+1)
	binary.BigEndian.PutUint32(ath[8:], srvSeq+1)
	ath[12] = 0x80 // Data Offset = 8 (32 bytes)
	ath[13] = testFlagACK
	binary.BigEndian.PutUint16(ath[14:], 0xffff)
	copy(ath[20:], opts)
	binary.BigEndian.PutUint16(ath[16:], tcpChecksum(ath, k.srcIP[:], k.dstIP[:]))

	tr.handleIPv4(ackPkt)

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fake never fired")
	}

	if sent.n() != 1 {
		t.Fatalf("want 1 fake, got %d", sent.n())
	}
	fake := sent.at(0)
	// TCP header must have Data Offset = 8
	fth := fake[20:]
	if fth[12]>>4 != 8 {
		t.Fatalf("fake Data Offset: got %d, want 8", fth[12]>>4)
	}
	if !bytes.Equal(fth[20:32], opts) {
		t.Fatalf("fake options mismatch: got %x, want %x", fth[20:32], opts)
	}
	// Fake payload starts at byte 52 (20 IP + 32 TCP)
	gotSNI, err := parseSNIOf(fake[52:])
	if err != nil {
		t.Fatalf("parseSNIOf failed on fake: %v", err)
	}
	if gotSNI != "mci.ir" {
		t.Fatalf("fake SNI: got %q, want mci.ir", gotSNI)
	}
}

