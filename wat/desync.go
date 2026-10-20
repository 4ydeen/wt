package wat

// Fake-SNI desync (client side; the raw-socket half is desync_linux.go). Right after a pool connection's TCP
// handshake completes, a raw packet carrying a fake TLS ClientHello with an allowlisted SNI is injected next to
// the real flow. A DPI that classifies flows by parsing the first TLS flight reads the fake and marks the flow as
// TLS to an allowlisted site; the real server drops the fake (out-of-window sequence number, or a TTL that dies at
// the censor's hop), so the relay then carries the session's own encrypted datagrams, which the DPI passes as TLS
// application data. Server-side changes: none. Reverse-engineered from patterniha/SNI-Spoofing (wrong-seq method,
// January 2026 whitelisting; see RESEARCH.md) with the trigger handling generalised after zapret's
// zero-stage/second-stage split: the fake can also be sent alongside (not only before) the real first flight.
//
// This file holds the OS-independent parts so the state machine is testable everywhere: the handshake tracker, the
// fake packet builder and the shared checksum helpers.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// htons swaps byte order for the socket option calls that take a network-order constant.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// csum is the internet checksum (also used by the ICMP carrier, icmp_linux.go).
func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// tcpChecksum computes the TCP checksum over the pseudo header, TCP header and payload.
func tcpChecksum(th, src, dst []byte) uint16 {
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6 // TCP
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	return csum(append(ph, th...))
}

// DesyncConfig tunes the fake-SNI layer of the tcp, tls, wss, h2 and grpc carriers.
type DesyncConfig struct {
	SNI  string // allowlisted server name the fake ClientHello carries
	Mode string // "seq" (wrong sequence number, default), "ttl" (small TTL), "sum" (valid window, bad checksum),
	             // "seqsum" (both markers per connection, ~1 ms apart; experimental, 2.8.0), or "rst" (bad-checksum RST)
	TTL  int    // ttl mode: hop count of the fake packet; 0 = calibrate it from the server's inbound TTL
}

// validateDesync checks a DesyncConfig the same way on every OS (NewDesync calls it before anything else).
func validateDesync(cfg DesyncConfig) error {
	if cfg.SNI == "" {
		return fmt.Errorf("wat: desync: empty SNI")
	}
	switch cfg.Mode {
	case "", "seq", "ttl", "sum", "seqsum", "rst":
	default:
		return fmt.Errorf("wat: -fake-mode must be seq, ttl, sum, seqsum or rst, got %q", cfg.Mode)
	}
	if cfg.TTL < 0 || cfg.TTL > 255 {
		return fmt.Errorf("wat: -fake-ttl must be 0 (auto) or 1..255, got %d", cfg.TTL)
	}
	return nil
}

// FakeClientHello builds a minimal TLS 1.2-format ClientHello carrying sni. The censor only parses it for the
// SNI; our own server never sees it, so there is no fingerprint to match and no handshake to complete.
func FakeClientHello(sni string) []byte {
	if sni == "" {
		return nil
	}
	sniB := []byte(sni)
	// server_name extension, standard layout: 0000 | ext_len | list_len | 00 (host name) | name_len | name
	ext := []byte{0, 0, byte((len(sniB) + 5) >> 8), byte(len(sniB) + 5), byte((len(sniB) + 3) >> 8), byte(len(sniB) + 3),
		0, byte(len(sniB) >> 8), byte(len(sniB))}
	ext = append(ext, sniB...)
	// supported_groups (secp256r1) and signature_algorithms (ecdsa_secp256r1_sha256): a TLS 1.2 ECDHE-ECDSA
	// handshake needs both, and a real parser checks them before the cipher choice.
	ext = append(ext, 0, 0x0a, 0, 6, 0, 4, 0, 0x17, 0, 0x18) // groups: x25519, secp256r1
	ext = append(ext, 0, 0x0d, 0, 4, 0, 2, 0x04, 0x03)       // sigalgs: ecdsa_secp256r1_sha256

	body := make([]byte, 0, 64+len(ext))
	body = append(body, 0x03, 0x03) // client version 1.2 in the clear, like every real ClientHello
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)
	body = append(body, 0)                            // session id length 0
	body = append(body, 0, 4, 0xc0, 0x2b, 0xc0, 0x23) // ECDHE-ECDSA-AES128-GCM-SHA256 / -AES128-SHA256
	body = append(body, 1, 0)                         // compression: null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

// parseSNIOf returns the SNI a ClientHello built by FakeClientHello carries (test helper).
func parseSNIOf(rec []byte) (string, error) {
	if len(rec) < 5 || rec[0] != 0x16 {
		return "", fmt.Errorf("not a handshake record")
	}
	l := int(rec[3])<<8 | int(rec[4])
	if len(rec) < 5+l {
		return "", fmt.Errorf("short record")
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		return "", fmt.Errorf("not a clienthello")
	}
	p := 4 + 2 + 32 // handshake header + client version + client random
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // skip session id
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	cs := int(hs[p])<<8 | int(hs[p+1])
	p += 2 + cs
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // compression methods
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	el := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	for off := 0; off+4 <= el && p+off+4 <= len(hs); {
		typ := int(hs[p+off])<<8 | int(hs[p+off+1])
		szl := int(hs[p+off+2])<<8 | int(hs[p+off+3])
		if typ == 0 { // server_name: list_len(2) | 00 (host name type) | name_len(2) | name
			q := p + off + 4
			if q+5 > len(hs) {
				break
			}
			nl := int(hs[q+3])<<8 | int(hs[q+4])
			if q+5+nl > len(hs) {
				break
			}
			return string(hs[q+5 : q+5+nl]), nil
		}
		off += 4 + szl
	}
	return "", fmt.Errorf("no sni")
}

// desyncPeerIP extracts the IP of a host:port peer (empty when unresolvable).
func desyncPeerIP(peer string) string {
	ip, _ := desyncPeerHostPort(peer)
	return ip
}

// desyncPeerHostPort splits a host:port peer into its IPv4 address and port (best effort, like desyncPeerIP).
func desyncPeerHostPort(peer string) (ip, port string) {
	if i := strings.IndexByte(peer, ','); i >= 0 {
		peer = strings.TrimSpace(peer[:i])
	}
	h, p, err := net.SplitHostPort(peer)
	if err != nil {
		h, p = peer, ""
	}
	if v := net.ParseIP(h); v != nil {
		return h, p
	}
	if addrs, err := net.LookupHost(h); err == nil && len(addrs) > 0 {
		for _, a := range addrs {
			if v := net.ParseIP(a); v != nil && v.To4() != nil {
				return a, p
			}
		}
		return addrs[0], p
	}
	return "", p
}

// desyncKey is one connection's outgoing 4-tuple (src = us). Inbound frames match the reversed key.
type desyncKey struct {
	srcIP [4]byte
	dstIP [4]byte
	srcPt uint16
	dstPt uint16
}

// fakePacket builds the IPv4+TCP+payload packet of one fake ClientHello. Pure: the same inputs build the same
// packet, so the tests pin it byte for byte (seq arithmetic, TTL, ack, checksum).
func fakePacket(k desyncKey, seq, ack uint32, ttl int, hello []byte) []byte {
	pkt := make([]byte, 20+20+len(hello))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[6] = 0x40 // Don't Fragment
	pkt[8] = byte(ttl)
	pkt[9] = 6 // TCP
	copy(pkt[12:16], k.srcIP[:])
	copy(pkt[16:20], k.dstIP[:])
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	copy(th[20:], hello)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]))
	return pkt
}

// fakeRSTPacket builds an in-window TCP RST+ACK packet with no payload. Pure: the same inputs build the same packet.
func fakeRSTPacket(k desyncKey, seq, ack uint32, ttl int) []byte {
	pkt := make([]byte, 20+20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[6] = 0x40 // Don't Fragment
	pkt[8] = byte(ttl)
	pkt[9] = 6 // TCP
	copy(pkt[12:16], k.srcIP[:])
	copy(pkt[16:20], k.dstIP[:])
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = 0x50
	th[13] = 0x14 // RST|ACK
	binary.BigEndian.PutUint16(th[14:], 0)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]))
	return pkt
}

// parseEthIPv4 returns the IPv4 packet carried by an ethernet frame, or nil (not IPv4 / truncated).
func parseEthIPv4(frame []byte) []byte {
	if len(frame) < 14+20 || binary.BigEndian.Uint16(frame[12:]) != 0x0800 {
		return nil
	}
	if ip := frame[14:]; ip[0]>>4 == 4 {
		return ip
	}
	return nil
}

// desyncTracker is the portable handshake state machine of the fake-SNI layer. The Linux injector feeds it every
// IPv4 packet of the wire (as raw IP byte slices, no ethernet header); tests feed it synthetic handshakes.
//
// Two trigger paths cover every dial order, because Wrap can only register a connection after dial returns and
// the SYN/SYN-ACK may already be gone by then:
//
//	early: Wrap knows the ISN (read off the socket with the TCP_REPAIR probe, or from a re-SYN on a tracked
//	       key). The fake fires on the first outbound segment at or after the stream start: the final ACK of
//	       the handshake, or the first data segment if that already went out. The fake precedes (or rides
//	       next to) the real first flight.
//	late:  the ISN is unknown (probe unavailable). The fake fires on the first outbound DATA segment seen on
//	       the announced key, its own sequence number derived from that segment's: same-segment-bundle
//	       desync, the zapret "disorder"/"fake,split" family. The real ClientHello is already on the wire,
//	       so this needs the classifier not to re-read the flow after it accepted the fake — the documented
//	       behaviour of the allowlist middleboxes of January 2026.
//
// Inbound SYN-ACKs of a tracked key cross-check the ack against the ISN: a NAT that rewrote our sequence numbers
// updates it, so the fake still lands below the stream start as the server sees it (seq mode's known failure
// becomes survivable when the shift is uniform). The inbound TTL of the peer is learned from any SYN-ACK from
// the peer IP, which is what calibrates -fake-mode ttl with -fake-ttl 0.
type desyncTracker struct {
	cfg       DesyncConfig
	peerIP    [4]byte
	hello     []byte
	send      func(pkt []byte) // set by the injector (raw socket) or a test (collector); nil = drop
	logf      func(string, ...any)
	mu        sync.Mutex
	conns     map[desyncKey]*desyncConn
	wait      map[desyncKey]chan struct{} // closed by fire, waited on by Wrap
	peerTTLv  uint8
	firedN    int
	miss      int
	missNoted bool
	closed    bool
}

type desyncConn struct {
	synSeq    uint32 // the ISN as the wire sees it (updated when a NAT rewrite is detected)
	isnKnown  bool   // early mode: the ISN is known before any data fires
	synAckSeq uint32 // seq of the server's SYN-ACK
	synAckAck uint32 // ack field of the server's SYN-ACK (== ISN+1)
	sumSeq    uint32 // sum/seqsum: seq of the outbound data segment being mirrored (0 = none yet)
	at        time.Time
}

// newDesyncTracker prepares the state machine for one peer IP.
func newDesyncTracker(cfg DesyncConfig, peerIP [4]byte) *desyncTracker {
	return &desyncTracker{cfg: cfg, peerIP: peerIP, hello: FakeClientHello(cfg.SNI),
		conns: map[desyncKey]*desyncConn{}, wait: map[desyncKey]chan struct{}{}}
}

// announce registers a connection Wrap is waiting for and returns its channel. known says the ISN is exact
// (from the socket probe); with known=false the tracker fires late, off the first data segment.
func (t *desyncTracker) announce(k desyncKey, isn uint32, known bool) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := make(chan struct{})
	if t.closed {
		close(ch)
		return ch
	}
	t.wait[k] = ch
	t.conns[k] = &desyncConn{synSeq: isn, isnKnown: known, at: time.Now()}
	return ch
}

// abandon drops a connection whose Wrap timed out (handshake never observed).
func (t *desyncTracker) abandon(k desyncKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch := t.wait[k]; ch != nil {
		delete(t.wait, k)
		close(ch)
	}
	delete(t.conns, k)
}

func (t *desyncTracker) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		for k, ch := range t.wait {
			close(ch)
			delete(t.wait, k)
		}
		t.conns = map[desyncKey]*desyncConn{}
	}
}

// fired reports how many fakes have been sent.
func (t *desyncTracker) fired() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.firedN
}

// peerTTL reports the learned inbound TTL of the peer (0 = not seen yet).
func (t *desyncTracker) peerTTL() uint8 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peerTTLv
}

// handleIPv4 advances the state machine with one raw IPv4 packet (header included, no ethernet header).
func (t *desyncTracker) handleIPv4(ip []byte) {
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 { // IPv4 TCP only, like the reference tool
		return
	}
	ihl := int(ip[0]&0xf) * 4
	if ihl < 20 || len(ip) < ihl+20 {
		return
	}
	th := ip[ihl:]
	if len(th) < 20 {
		return
	}
	off := int(th[12]>>4) * 4
	if off < 20 || len(th) < off {
		return
	}
	var s, d [4]byte
	copy(s[:], ip[12:16])
	copy(d[:], ip[16:20])
	sport, dport := binary.BigEndian.Uint16(th[0:]), binary.BigEndian.Uint16(th[2:])
	out := desyncKey{s, d, sport, dport}
	in := desyncKey{d, s, dport, sport}
	seq, ackv := binary.BigEndian.Uint32(th[4:]), binary.BigEndian.Uint32(th[8:])
	syn, ackf, rst := th[13]&0x02 != 0, th[13]&0x10 != 0, th[13]&0x04 != 0
	payload := len(th) - off

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	now := time.Now()
	// any SYN-ACK from the peer teaches the inbound TTL (ttl auto-calibration), tracked or not
	if syn && ackf && payload == 0 && !rst && s == t.peerIP && t.peerTTLv == 0 {
		t.peerTTLv = ip[8]
	}
	// our outgoing SYN on a tracked key: (re)learn the ISN from the wire
	if c := t.conns[out]; c != nil && syn && !ackf && payload == 0 && !rst {
		if !c.isnKnown || seq != c.synSeq {
			c.synSeq, c.isnKnown, c.synAckSeq, c.synAckAck = seq, true, 0, 0
		}
		c.at = now
		return
	}
	// inbound SYN-ACK for a tracked conn: remember its seq/ack, and follow a NAT that rewrote our ISN
	if c := t.conns[in]; c != nil && syn && ackf && payload == 0 && !rst {
		if c.isnKnown && ackv != c.synSeq+1 {
			c.synSeq = ackv - 1 // uniform rewrite: the server's stream starts here now
		}
		c.synAckSeq, c.synAckAck, c.at = seq, ackv, now
		return
	}
	if rst {
		return
	}
	c := t.conns[out]
	if c == nil || c.synAckAck == 0 && !c.isnKnown {
		return // nothing to anchor the fake's ack to yet
	}
	switch {
	case c.isnKnown:
		// early: fire on the handshake's final ACK or the first data flight, whichever comes first.
		// sum/seqsum modes stay for the first DATA segment: their fake is a valid-window duplicate of that
		// segment, so it needs the segment's real seq/ack to be identical to the real flight (bare ACKs have
		// nothing to mirror). The mirror base lives on the connection (2.8.1): it was tracker-global, so two
		// pool connections opening at once cross-set it and the second fire mirrored the wrong segment.
		if !syn && ackf && seq-c.synSeq+1 < 0x80000000 {
			if sumMode := t.cfg.Mode == "sum" || t.cfg.Mode == "seqsum" || t.cfg.Mode == "rst"; sumMode {
				if payload == 0 {
					return // wait for the data segment to mirror
				}
				c.sumSeq = seq
			}
			t.fireLocked(out, c, c.synSeq+1, ackv)
		}
	default:
		// late: the first outbound data segment is the anchor (its seq IS the stream start)
		if payload > 0 && ackf && !syn {
			if t.cfg.Mode == "sum" || t.cfg.Mode == "seqsum" || t.cfg.Mode == "rst" {
				c.sumSeq = seq
			}
			t.fireLocked(out, c, seq, ackv)
		}
	}
}

// fireLocked builds and sends the fake for one completed handshake (mu held).
func (t *desyncTracker) fireLocked(k desyncKey, c *desyncConn, base, ack uint32) {
	ttl := 64
	if t.cfg.Mode == "ttl" {
		ttl = t.cfg.TTL
		if ttl <= 0 { // auto: one hop less than the distance the server's packets travel
			if p := int(t.peerTTLv); p > 1 {
				ttl = p - 1
			} else {
				t.miss++
				if !t.missNoted {
					t.missNoted = true
					if t.logf != nil {
						t.logf("wat: fake-sni ttl auto: the peer's TTL is not learned yet, handshake left unclassified (calibrates from the first SYN-ACK)")
					}
				}
				return
			}
		}
	}
	// sum mode mirrors the triggering data segment: identical seq (so the fake sits in the receiver window where
	// the DPI's reassembler is already collecting), identical ack, but a deliberately damaged TCP checksum — the
	// same fooling as GoodbyeDPI's --wrong-chksum and zapret's badsum. The server's kernel drops it at checksum
	// validation; a DPI that parses before checksumming reads the SNI. NATs that validate checksums
	// (nf_conntrack_checksum=1 + an INVALID-drop FORWARD rule) kill this mode; ISPs usually pass (zapret's
	// documented field observation).
	sumMode := t.cfg.Mode == "sum" || t.cfg.Mode == "seqsum" || t.cfg.Mode == "rst"
	if sumMode {
		base = c.sumSeq
	}
	// seq = base - len(fake): the fake lands exactly below the stream start. The server holds snd_una at the
	// stream start, so this is an old duplicate; a DPI without window checks reassembles it as the first flight.
	t.firedN++
	delete(t.conns, k)
	if ch := t.wait[k]; ch != nil {
		delete(t.wait, k)
		close(ch)
	}
	if t.send != nil {
		if t.cfg.Mode == "rst" {
			// rst mode sends an in-window RST|ACK with damaged checksum: middleboxes clear flow state,
			// while the server kernel drops corrupted checksum packets before parsing flags.
			pkt := fakeRSTPacket(k, base, ack, ttl)
			damageChecksum(pkt)
			t.send(pkt)
			return
		}
		if t.cfg.Mode == "seqsum" {
			// dual marker (2.8.0): the below-window seq fake first, then the in-window bad-checksum mirror
			// ~1 ms later (GoodbyeDPI sends wrong-seq + wrong-chksum as two fakes per connection). A filter
			// must discard BOTH correctly to miss the SNI: window-junk dropping alone does not stop the sum
			// marker, checksum dropping alone does not stop the seq marker. Both still die before the server.
			t.send(fakePacket(k, base-uint32(len(t.hello)), ack, ttl, t.hello))
			pkt := fakePacket(k, base, ack, ttl, t.hello)
			damageChecksum(pkt)
			t.send(pkt)
			return
		}
		if t.cfg.Mode == "sum" {
			// sum mode mirrors the triggering data segment: in-window seq (base = c.sumSeq), damaged checksum
			pkt := fakePacket(k, base, ack, ttl, t.hello)
			damageChecksum(pkt)
			t.send(pkt)
			return
		}
		pkt := fakePacket(k, base-uint32(len(t.hello)), ack, ttl, t.hello)
		t.send(pkt)
	}
}

// damageChecksum rewrites a valid TCP checksum into an invalid one, unconditionally: s-1, but when that would
// wrap to 0xffff (a VALID fold: the internet checksum of a correct packet is 0xffff by definition) it goes to
// s-2 instead. The 2.7.1 formula (s^1)-1 was an IDENTITY for every even s — (s+1)-1 = s — so on average every
// second sum-marker shipped with a fully valid checksum and the server would have accepted its payload as real
// stream data. Found by the sum-mode test flaking with ~50 % frequency (the SNI random bytes decide the parity).
func damageChecksum(pkt []byte) {
	s := binary.BigEndian.Uint16(pkt[20+16:])
	d := s - 1
	if d == 0xffff {
		d = s - 2
	}
	binary.BigEndian.PutUint16(pkt[20+16:], d)
}
