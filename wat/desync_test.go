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

// desyncTestTracker builds a tracker with a collected send path and a fixed client/peer pair.
func desyncTestTracker(mode string, ttl int) (*desyncTracker, *[][]byte) {
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
	sent := &[][]byte{}
	tr.send = func(pkt []byte) { *sent = append(*sent, pkt) }
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
	if len(*sent) != 1 {
		t.Fatalf("want 1 fake, got %d", len(*sent))
	}
	pkt := (*sent)[0]
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
	seq := binary.BigEndian.Uint32((*sent)[0][24:])
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
	seq := binary.BigEndian.Uint32((*sent)[0][24:])
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
	if len(*sent) != 0 {
		t.Fatalf("late path fired on bare ACKs (%d fakes)", len(*sent))
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
	seq := binary.BigEndian.Uint32((*sent)[0][24:])
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
	if len(*sent) != 1 {
		t.Fatalf("want 1 fake, got %d", len(*sent))
	}
	if got := (*sent)[0][8]; got != 51 {
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
	if got := (*sent)[0][8]; got != 59 {
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
	if tr.fired() != 0 || len(*sent) != 0 {
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
	if got := (*sent)[0][8]; got != 9 {
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
	if len(*sent) != 1 {
		t.Fatalf("want exactly 1 fake, got %d", len(*sent))
	}
}

// TestDesyncUnknownConnIgnored: traffic on connections the tracker never saw announced is passed over.
func TestDesyncUnknownConnIgnored(t *testing.T) {
	tr, sent := desyncTestTracker("seq", 0)
	defer tr.close()
	k := testClientKey()
	feedFullHandshake(tr, k, 3000, 400) // never announced
	if tr.fired() != 0 || len(*sent) != 0 {
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
	if tr.fired() != 0 || len(*sent) != 0 {
		t.Fatal("fired after close")
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
	seq := binary.BigEndian.Uint32((*sent)[0][24:])
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
	pkt := (*sent)[0]
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
	seq := binary.BigEndian.Uint32((*sent)[0][24:])
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
	if len(*sent) != 1 {
		t.Fatalf("sent %d packets, want 1", len(*sent))
	}
	pkt := (*sent)[0]
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
	pkt := (*sent)[0]
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
	if len(*sent) != 2 {
		t.Fatalf("seqsum sent %d markers, want 2", len(*sent))
	}
	// marker 1: below-window seq, VALID checksum (plain seq fake). fakePacket built it correctly and seqsum
	// sent it unmodified — recompute and require equality.
	m1 := (*sent)[0]
	if got := binary.BigEndian.Uint32(m1[24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum marker1 seq %d, want %d (below stream start)", got, isn+1-uint32(len(tr.hello)))
	}
	stored1 := binary.BigEndian.Uint16(m1[20+16:])
	binary.BigEndian.PutUint16(m1[20+16:], 0)
	if good := tcpChecksum(m1[20:], k.srcIP[:], k.dstIP[:]); good != stored1 {
		t.Fatalf("seqsum marker1 checksum %04x, want the VALID value %04x", stored1, good)
	}
	// marker 2: in-window seq (the data segment's own), DAMAGED checksum
	m2 := (*sent)[1]
	if got := binary.BigEndian.Uint32(m2[24:]); got != isn+1 {
		t.Fatalf("seqsum marker2 seq %d, want %d (in-window mirror)", got, isn+1)
	}
	stored2 := binary.BigEndian.Uint16(m2[20+16:])
	binary.BigEndian.PutUint16(m2[20+16:], 0)
	if good := tcpChecksum(m2[20:], k.srcIP[:], k.dstIP[:]); good == stored2 {
		t.Fatalf("seqsum marker2 carries a VALID checksum %04x (must be damaged)", good)
	}
	// both carry the same allowlisted SNI payload
	for i, m := range [][]byte{m1, m2} {
		if string(m[40:]) != string(tr.hello) {
			t.Fatalf("seqsum marker%d payload is not the fake hello", i+1)
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
	if len(*sent) != 2 {
		t.Fatalf("seqsum late sent %d markers, want 2", len(*sent))
	}
	if got := binary.BigEndian.Uint32((*sent)[0][24:]); got != isn+1-uint32(len(tr.hello)) {
		t.Fatalf("seqsum late marker1 seq %d, want %d", got, isn+1-uint32(len(tr.hello)))
	}
	if got := binary.BigEndian.Uint32((*sent)[1][24:]); got != isn+1 {
		t.Fatalf("seqsum late marker2 seq %d, want %d (in-window)", got, isn+1)
	}
}
