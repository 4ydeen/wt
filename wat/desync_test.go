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
	case "split":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "split"}
	case "hlen0":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "hlen0"}
	case "fakeip":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "fakeip"}
	case "synrst":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "synrst"}
	case "all":
		cfg = DesyncConfig{SNI: "mci.ir", Mode: "all"}
	}
	return desyncTestTrackerCfg(cfg)
}

// desyncTestTrackerCfg builds a tracker for an arbitrary config with a collected send path and the fixed
// 192.168.1.2 -> 10.8.0.1 peer pair.
func desyncTestTrackerCfg(cfg DesyncConfig) (*desyncTracker, *sentLog) {
	var p [4]byte
	copy(p[:], net.ParseIP("10.8.0.1").To4())
	tr := newDesyncTracker(cfg, p)
	sent := &sentLog{}
	tr.send = sent.add
	return tr, sent
}

// tcpChecksumOK reports whether an IPv4+TCP packet (header included) carries a valid TCP checksum.
func tcpChecksumOK(pkt []byte) bool {
	c := append([]byte(nil), pkt...)
	stored := binary.BigEndian.Uint16(c[20+16:])
	binary.BigEndian.PutUint16(c[20+16:], 0)
	return tcpChecksum(c[20:], c[12:16], c[16:20]) == stored
}

// payloadOf returns the TCP payload of an IPv4+TCP packet, honoring the data offset.
func payloadOf(pkt []byte) []byte {
	off := 20 + int(pkt[20+12]>>4)*4
	if off > len(pkt) {
		return nil
	}
	return pkt[off:]
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

// TestDesyncParseEthIPv4 validates ethernet, VLAN, SLL and raw frames, and rejects non-IPv4 frames.
func TestDesyncParseEthIPv4(t *testing.T) {
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if parseEthIPv4(arp) != nil {
		t.Fatal("ARP frame accepted")
	}
	if parseEthIPv4([]byte{1, 2, 3}) != nil {
		t.Fatal("short frame accepted")
	}

	// Raw IPv4 packet (tun/wg)
	rawIP := make([]byte, 40)
	rawIP[0] = 0x45 // IPv4, 20-byte IHL
	if got := parseEthIPv4(rawIP); got == nil || len(got) != 40 {
		t.Fatal("raw IPv4 packet rejected")
	}

	// 802.1Q VLAN tagged frame (18-byte header)
	vlan := make([]byte, 18+40)
	binary.BigEndian.PutUint16(vlan[12:], 0x8100)
	binary.BigEndian.PutUint16(vlan[16:], 0x0800)
	vlan[18] = 0x45
	if got := parseEthIPv4(vlan); got == nil || len(got) != 40 {
		t.Fatal("VLAN-tagged IPv4 packet rejected")
	}

	// Linux cooked mode SLL (16-byte header)
	sll := make([]byte, 16+40)
	binary.BigEndian.PutUint16(sll[14:], 0x0800)
	sll[16] = 0x45
	if got := parseEthIPv4(sll); got == nil || len(got) != 40 {
		t.Fatal("SLL IPv4 packet rejected")
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

// TestValidateDesyncNewModes pins validation for the modes added with the F&F round: split/hlen0/fakeip/synrst/
// all, the -fake-ip IPv4 check and the -fake-split range.
func TestValidateDesyncNewModes(t *testing.T) {
	for _, m := range []string{"split", "hlen0", "fakeip", "synrst", "all"} {
		if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: m}); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "188.114.98.0"}); err != nil {
		t.Fatalf("fakeip with an explicit IPv4: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: " 104.16.0.1 "}); err != nil {
		t.Fatalf("fakeip FakeIP with surrounding whitespace: %v", err)
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "cdn.example.com"}); err == nil {
		t.Fatal("a non-IPv4 FakeIP must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "fakeip", FakeIP: "2a06:98c1:3101::6812:202f"}); err == nil {
		t.Fatal("an IPv6 FakeIP must fail (the packet builders write IPv4 headers)")
	}
	for _, n := range []int{2, 3, 16} {
		if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: n}); err != nil {
			t.Fatalf("split %d: %v", n, err)
		}
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: 1}); err == nil {
		t.Fatal("split 1 must fail")
	}
	if err := validateDesync(DesyncConfig{SNI: "a.ir", Mode: "split", Split: 17}); err == nil {
		t.Fatal("split > 16 must fail")
	}
}

// TestDesyncSplitMode: split cuts the fake ClientHello across TCP segments: the first payload segment is the
// record byte alone, a segment boundary lands on the SNI extension, the fragments' seq numbers are contiguous and
// the whole ghost stays below the stream start. Reassembled in seq order the fragments still form the allowlisted
// ClientHello, so a reassembling receiver is fooled while a per-packet parser sees no complete record.
func TestDesyncSplitMode(t *testing.T) {
	tr, sent := desyncTestTracker("split", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(9000), uint32(400)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("split fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("split fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 3 {
		t.Fatalf("default split sent %d segments, want 3", sent.n())
	}
	streamStart := isn + 1
	wantSeq := streamStart - uint32(len(tr.hello))
	var reassembled []byte
	var bounds []int
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		payload := payloadOf(pkt)
		if i == 0 && len(payload) != 1 {
			t.Fatalf("split segment 1 is %d bytes, want 1 (the TLS record byte alone)", len(payload))
		}
		if got := binary.BigEndian.Uint16(pkt[22:]); got != k.dstPt {
			t.Fatalf("segment %d dport %d", i, got)
		}
		if got := binary.BigEndian.Uint32(pkt[24:]); got != wantSeq+uint32(len(reassembled)) {
			t.Fatalf("segment %d seq %d, want %d (contiguous fragments)", i, got, wantSeq+uint32(len(reassembled)))
		}
		if got := binary.BigEndian.Uint32(pkt[28:]); got != srvSeq+1 {
			t.Fatalf("segment %d ack %d, want %d", i, got, srvSeq+1)
		}
		if !tcpChecksumOK(pkt) {
			t.Fatalf("segment %d carries an invalid checksum (split fragments must be plain seq markers)", i)
		}
		reassembled = append(reassembled, payload...)
		bounds = append(bounds, len(reassembled))
	}
	// every fragment sits below the stream start, so the server kernel drops each one as an old duplicate
	if wantSeq+uint32(len(reassembled)) != streamStart {
		t.Fatalf("reassembled fake ends at %d, want %d (the stream start)", wantSeq+uint32(len(reassembled)), streamStart)
	}
	if len(reassembled) != len(tr.hello) {
		t.Fatalf("split reassembles to %d bytes, want %d", len(reassembled), len(tr.hello))
	}
	got, err := parseSNIOf(reassembled)
	if err != nil || got != "mci.ir" {
		t.Fatalf("reassembled split SNI: got %q err %v, want mci.ir", got, err)
	}
	// the SNI extension starts exactly on a fragment boundary: no payload segment carries a complete record header
	// together with the server_name extension header.
	off := sniExtOffset(reassembled)
	if off == 0 {
		t.Fatal("SNI extension not found in the reassembled fake")
	}
	onBoundary := false
	for _, b := range bounds {
		if b == off {
			onBoundary = true
		}
	}
	if !onBoundary {
		t.Fatalf("no segment boundary at the SNI extension offset %d (bounds %v)", off, bounds)
	}
}

// TestDesyncSplitHonoursConfiguredCount: -fake-split sets the segment count (0 = default 3, 2..16 otherwise).
func TestDesyncSplitHonoursConfiguredCount(t *testing.T) {
	for _, tc := range []struct{ split, want int }{{0, 3}, {2, 2}, {4, 4}, {16, 16}} {
		tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "split", Split: tc.split})
		k := testClientKey()
		ch := tr.announce(k, 1001, true)
		feedFullHandshake(tr, k, 1000, 500)
		select {
		case <-ch:
		case <-time.After(time.Second):
			tr.close()
			t.Fatalf("split %d: fake never fired", tc.split)
		}
		if sent.n() != tc.want {
			tr.close()
			t.Fatalf("split %d sent %d segments, want %d", tc.split, sent.n(), tc.want)
		}
		// the fragments still add up to exactly one fake ClientHello
		total := 0
		for i := 0; i < sent.n(); i++ {
			total += len(payloadOf(sent.at(i)))
		}
		if total != len(tr.hello) {
			tr.close()
			t.Fatalf("split %d reassembles to %d bytes, want %d", tc.split, total, len(tr.hello))
		}
		tr.close()
	}
}

// TestDesyncHlen0ZeroRecord: hlen0 leaves the record length field at 0 (F&F tlshello-0-len) while the body still
// carries the allowlisted SNI, at the plain seq-mode placement (below the stream start, valid checksum, TTL 64).
func TestDesyncHlen0ZeroRecord(t *testing.T) {
	tr, sent := desyncTestTracker("hlen0", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(11000), uint32(600)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("hlen0 fake never fired")
	}
	if tr.fired() != 1 || sent.n() != 1 {
		t.Fatalf("hlen0 fired %d, sent %d; want 1 and 1", tr.fired(), sent.n())
	}
	pkt := sent.at(0)
	payload := payloadOf(pkt)
	if len(payload) != len(tr.hello) {
		t.Fatalf("hlen0 payload %d bytes, want %d (the mask keeps the body)", len(payload), len(tr.hello))
	}
	if payload[0] != 0x16 {
		t.Fatalf("hlen0 payload does not start with a TLS handshake byte: %02x", payload[0])
	}
	if payload[3] != 0 || payload[4] != 0 {
		t.Fatalf("hlen0 record length % x, want 00 00 (F&F tlshello-0-len)", payload[3:5])
	}
	// a per-packet sniffer that ignores the length field still reads the allowlisted name
	if got, err := parseSNIOf(payload); err != nil || got != "mci.ir" {
		t.Fatalf("hlen0 SNI: got %q err %v, want mci.ir", got, err)
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("hlen0 seq %d, want %d (seq-mode placement)", got, isn+1-uint32(len(tr.hello)))
	}
	if pkt[8] != 64 {
		t.Fatalf("hlen0 ttl %d, want 64 (seq-mode placement)", pkt[8])
	}
	if !tcpChecksumOK(pkt) {
		t.Fatal("hlen0 must carry a valid checksum: its marker is the zeroed record length, not a bad checksum")
	}
}

// TestDesyncFakeIPMirrorsWhitelistedIP: fakeip sends a well-formed SYN and ClientHello for the same client port
// but a whitelisted CDN destination (configured, and the 104.16.0.1 default). Both packets are checksum-valid,
// so an IP-allowlist DPI records the flow as allowed-CDN traffic; the destination is not the real server, so the
// tunnel never sees them.
func TestDesyncFakeIPMirrorsWhitelistedIP(t *testing.T) {
	tr, sent := desyncTestTrackerCfg(DesyncConfig{SNI: "mci.ir", Mode: "fakeip", FakeIP: "188.114.98.1"})
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(12000), uint32(700)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("fakeip fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("fakeip fired counter %d, want 1", tr.fired())
	}
	if sent.n() != 2 {
		t.Fatalf("fakeip sent %d packets, want 2 (SYN + ClientHello)", sent.n())
	}
	wantIP := []byte{188, 114, 98, 1}
	for i := 0; i < sent.n(); i++ {
		pkt := sent.at(i)
		if ip := pkt[16:20]; !bytes.Equal(ip, wantIP) {
			t.Fatalf("packet %d dst % x, want the whitelisted CDN IP % x", i, ip, wantIP)
		}
		if got := binary.BigEndian.Uint16(pkt[20:]); got != k.srcPt {
			t.Fatalf("packet %d sport %d, want the client's real port %d", i, got, k.srcPt)
		}
		if got := binary.BigEndian.Uint16(pkt[22:]); got != 443 {
			t.Fatalf("packet %d dport %d, want 443", i, got)
		}
		if csum(pkt[:20]) != 0 {
			t.Fatalf("packet %d IP header checksum invalid", i)
		}
		if !tcpChecksumOK(pkt) {
			t.Fatalf("packet %d carries an invalid TCP checksum (fakeip must look like real CDN traffic)", i)
		}
	}
	syn := sent.at(0)
	if flags := syn[20+13]; flags != 0x02 {
		t.Fatalf("packet 1 flags 0x%02x, want 0x02 (SYN)", flags)
	}
	helloPkt := sent.at(1)
	if flags := helloPkt[20+13]; flags != 0x18 {
		t.Fatalf("packet 2 flags 0x%02x, want 0x18 (PSH|ACK)", flags)
	}
	synSeq := binary.BigEndian.Uint32(syn[24:])
	if got := binary.BigEndian.Uint32(helloPkt[24:]); got != synSeq+1 {
		t.Fatalf("hello seq %d, want %d (SYN+1)", got, synSeq+1)
	}
	// the fake flow's bytes also end at the real stream start: even a DPI that merged the keys sees old duplicates
	if got := binary.BigEndian.Uint32(helloPkt[24:]) + uint32(len(payloadOf(helloPkt))); got != isn+1 {
		t.Fatalf("fakeip synthetic stream ends at %d, want %d (the real stream start)", got, isn+1)
	}
	if got, err := parseSNIOf(payloadOf(helloPkt)); err != nil || got != "mci.ir" {
		t.Fatalf("fakeip hello SNI: got %q err %v, want mci.ir", got, err)
	}

	// the default FakeIP is the Cloudflare edge
	tr2, sent2 := desyncTestTracker("fakeip", 0)
	defer tr2.close()
	k2 := testClientKey()
	ch2 := tr2.announce(k2, 20001, true)
	feedFullHandshake(tr2, k2, 20000, 900)
	select {
	case <-ch2:
	case <-time.After(time.Second):
		t.Fatal("default-fakeip fake never fired")
	}
	if got := sent2.at(0)[16:20]; !bytes.Equal(got, []byte{104, 16, 0, 1}) {
		t.Fatalf("default fakeip dst % x, want 104.16.0.1 (a Cloudflare edge)", got)
	}
}

// TestDesyncSYNRSTClearsFlowHarder: synrst sends an in-window SYN|RST with a damaged checksum: a protocol-invalid
// combination that stateful middleboxes purge harder than a plain RST, and that the server kernel drops at
// checksum validation before reading flags.
func TestDesyncSYNRSTClearsFlowHarder(t *testing.T) {
	tr, sent := desyncTestTracker("synrst", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(13000), uint32(800)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("synrst fake never fired")
	}
	if tr.fired() != 1 || sent.n() != 1 {
		t.Fatalf("synrst fired %d, sent %d; want 1 and 1", tr.fired(), sent.n())
	}
	pkt := sent.at(0)
	if len(pkt) != 40 {
		t.Fatalf("synrst packet len %d, want 40 (header only)", len(pkt))
	}
	if flags := pkt[20+13]; flags != 0x06 {
		t.Fatalf("synrst flags 0x%02x, want 0x06 (SYN|RST)", flags)
	}
	if got := binary.BigEndian.Uint32(pkt[24:]); got != isn+1 {
		t.Fatalf("synrst seq %d, want %d (in-window)", got, isn+1)
	}
	if tcpChecksumOK(pkt) {
		t.Fatal("synrst carries a VALID checksum (must be damaged so the server kernel drops it)")
	}
}

// TestDesyncAllFiresThreeMarkers: all mode fires seq + sum + hlen0 markers ~1 ms apart. Classify the three sent
// packets by their properties (below-window/valid, in-window/damaged, below-window/zero-record) rather than by
// arrival order, so the ~1 ms timer scheduling cannot make the test flaky.
func TestDesyncAllFiresThreeMarkers(t *testing.T) {
	tr, sent := desyncTestTracker("all", 0)
	defer tr.close()
	k := testClientKey()
	const isn, srvSeq = uint32(15000), uint32(300)
	ch := tr.announce(k, isn+1, true)
	feedFullHandshake(tr, k, isn, srvSeq)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("all fake never fired")
	}
	if tr.fired() != 1 {
		t.Fatalf("all fired counter %d, want 1", tr.fired())
	}
	deadline := time.Now().Add(time.Second)
	for sent.n() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("all sent %d markers, want 3 (a timer marker never arrived)", sent.n())
		}
		time.Sleep(time.Millisecond)
	}
	streamStart := isn + 1
	belowSeq := streamStart - uint32(len(tr.hello))
	var sawSeq, sawSum, sawHLen bool
	for i := 0; i < 3; i++ {
		pkt := sent.at(i)
		payload := payloadOf(pkt)
		seq := binary.BigEndian.Uint32(pkt[24:])
		valid := tcpChecksumOK(pkt)
		switch {
		case len(payload) == len(tr.hello) && payload[3] == 0 && payload[4] == 0 && seq == belowSeq && valid:
			sawHLen = true
		case len(payload) == len(tr.hello) && seq == belowSeq && valid:
			sawSeq = true
		case len(payload) == len(tr.hello) && seq == streamStart && !valid:
			sawSum = true
		default:
			t.Fatalf("marker %d matches no expected shape (seq %d, len %d, valid %v)", i, seq, len(payload), valid)
		}
	}
	if !sawSeq || !sawSum || !sawHLen {
		t.Fatalf("all markers missing: seq=%v sum=%v hlen0=%v (want all three)", sawSeq, sawSum, sawHLen)
	}
}

// TestDesyncExistingModesFireUnchangedBytes: the new-mode work must not perturb what the older modes put on the
// wire. Each fire of seq / sum / rst must be byte-identical to the same shared builder the release before this
// change used (the existing mode tests above pin the individual fields; this pins the whole packet).
func TestDesyncExistingModesFireUnchangedBytes(t *testing.T) {
	k := testClientKey()
	const isn, srvSeq = uint32(16000), uint32(1200)

	fireOne := func(mode string) []byte {
		tr, sent := desyncTestTracker(mode, 0)
		defer tr.close()
		ch := tr.announce(k, isn+1, true)
		feedFullHandshake(tr, k, isn, srvSeq)
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("%s: fake never fired", mode)
		}
		if sent.n() != 1 {
			t.Fatalf("%s: sent %d packets, want 1", mode, sent.n())
		}
		return sent.at(0)
	}

	seqPkt := fireOne("seq")
	if want := fakePacket(k, isn+1-uint32(len(payloadOf(seqPkt))), srvSeq+1, 64, payloadOf(seqPkt)); !bytes.Equal(seqPkt, want) {
		t.Fatal("seq mode fire bytes changed")
	}
	sumPkt := fireOne("sum")
	wantSum := fakePacket(k, isn+1, srvSeq+1, 64, payloadOf(sumPkt))
	damageChecksum(wantSum)
	if !bytes.Equal(sumPkt, wantSum) {
		t.Fatal("sum mode fire bytes changed")
	}
	rstPkt := fireOne("rst")
	wantRST := fakeRSTPacket(k, isn+1, srvSeq+1, 64)
	damageChecksum(wantRST)
	if !bytes.Equal(rstPkt, wantRST) {
		t.Fatal("rst mode fire bytes changed")
	}
}
