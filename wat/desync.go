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
	"sync/atomic"
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

// splitSNIs splits a comma-separated list of SNIs into trimmed domain names.
func splitSNIs(sni string) []string {
	var out []string
	for _, s := range strings.Split(sni, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// validateDesync checks a DesyncConfig the same way on every OS (NewDesync calls it before anything else).
func validateDesync(cfg DesyncConfig) error {
	snis := splitSNIs(cfg.SNI)
	if len(snis) == 0 {
		return fmt.Errorf("wat: desync: empty SNI")
	}
	for _, s := range snis {
		if strings.ContainsAny(s, " \t\r\n/") {
			return fmt.Errorf("wat: desync: invalid SNI %q", s)
		}
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

// FakeClientHello builds a realistic, RFC 8446-compliant TLS 1.3/1.2 ClientHello carrying sni.
// It includes modern TLS 1.3 extensions (supported_versions, ALPN h2/http/1.1, key_share X25519,
// supported_groups, signature_algorithms, and psk_key_exchange_modes) so heuristic middlebox
// parsers classify the flow with 100% confidence as standard modern browser HTTPS web browsing.
func FakeClientHello(sni string) []byte {
	if sni == "" {
		return nil
	}
	sniB := []byte(sni)
	// 1. server_name extension: 0000 | ext_len | list_len | 00 (host name) | name_len | name
	ext := []byte{0, 0, byte((len(sniB) + 5) >> 8), byte(len(sniB) + 5), byte((len(sniB) + 3) >> 8), byte(len(sniB) + 3),
		0, byte(len(sniB) >> 8), byte(len(sniB))}
	ext = append(ext, sniB...)

	// 2. supported_versions: length 5 (list len 4: 0x0304 TLS 1.3, 0x0303 TLS 1.2)
	ext = append(ext, 0, 0x2b, 0, 5, 4, 0x03, 0x04, 0x03, 0x03)

	// 3. alpn: h2, http/1.1 (list len 12, ext len 14)
	ext = append(ext, 0, 0x10, 0, 14, 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1')

	// 4. supported_groups: x25519, secp256r1, secp384r1 (list len 6, ext len 8)
	ext = append(ext, 0, 0x0a, 0, 8, 0, 6, 0, 0x1d, 0, 0x17, 0, 0x18)

	// 5. key_share: group x25519 (0x001d), key exchange length 32 (list len 36, ext len 38)
	var keyShare [32]byte
	_, _ = rand.Read(keyShare[:])
	ext = append(ext, 0, 0x33, 0, 38, 0, 36, 0, 0x1d, 0, 32)
	ext = append(ext, keyShare[:]...)

	// 6. signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256 (list len 6, ext len 8)
	ext = append(ext, 0, 0x0d, 0, 8, 0, 6, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01)

	// 7. psk_key_exchange_modes: psk_dhe_ke (list len 1, ext len 2)
	ext = append(ext, 0, 0x2d, 0, 2, 1, 1)

	// 8. encrypted_client_hello (ECH GREASE, RFC 9460 §6.1 / RFC 8701 / draft-ietf-tls-esni-22):
	// Modern browsers (Chrome 117+, Firefox 118+) attach an outer ECH GREASE extension by default.
	// Middleboxes cannot decrypt inner ClientHellos, forcing allowlist classifiers to evaluate the
	// outer server_name, while JA4 heuristic analyzers validate authentic browser extension composition.
	echData := make([]byte, 0, 138)
	echData = append(echData, 0x00)                     // outer
	echData = append(echData, 0x00, 0x01, 0x00, 0x01) // HKDF-SHA256, AES-128-GCM
	echData = append(echData, 0x00)                     // config_id
	var echEnc [32]byte
	_, _ = rand.Read(echEnc[:])
	echData = append(echData, 0x00, 32)
	echData = append(echData, echEnc[:]...)
	var echPayload [96]byte
	_, _ = rand.Read(echPayload[:])
	echData = append(echData, 0x00, 96)
	echData = append(echData, echPayload[:]...)

	ext = append(ext, 0xfe, 0x0d, byte(len(echData)>>8), byte(len(echData)))
	ext = append(ext, echData...)

	body := make([]byte, 0, 128+len(ext))
	body = append(body, 0x03, 0x03) // client version 1.2 in ClientHello body (RFC 8446)
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)

	// 32-byte session ID (RFC 8446 middlebox compatibility mode)
	var sid [32]byte
	_, _ = rand.Read(sid[:])
	body = append(body, 32)
	body = append(body, sid[:]...)

	// Cipher suites: TLS 1.3 (AES-128, AES-256, ChaCha20) + TLS 1.2 ECDHE (ECDSA/RSA)
	body = append(body, 0, 12,
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03, // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
		0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x23, // ECDHE-ECDSA-AES128-GCM, ECDHE-RSA-AES128-GCM, ECDHE-ECDSA-AES128-SHA256
	)
	body = append(body, 1, 0) // compression: null
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

// fakePacketWithOptions builds the IPv4+TCP+options+payload packet of one fake ClientHello.
// When opts is non-empty (e.g. Linux kernel TCP timestamps NOP, NOP, TSval, TSecr), the segment
// mirrors standard kernel packet formatting (Data Offset > 5) so DPI appliances performing
// TCP option consistency validation cannot distinguish the injected marker from normal traffic.
func fakePacketWithOptions(k desyncKey, seq, ack uint32, ttl int, hello []byte, opts []byte) []byte {
	tcpHdrLen := 20 + len(opts)
	pad := (4 - (tcpHdrLen % 4)) % 4
	tcpHdrLen += pad
	dataOffset := byte(tcpHdrLen / 4)

	pkt := make([]byte, 20+tcpHdrLen+len(hello))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[6] = 0x40 // Don't Fragment
	pkt[8] = byte(ttl)
	pkt[9] = 6 // TCP
	copy(pkt[12:16], k.srcIP[:])
	copy(pkt[16:20], k.dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:], csum(pkt[:20]))

	th := pkt[20 : 20+tcpHdrLen]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], ack)
	th[12] = dataOffset << 4
	th[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	if len(opts) > 0 {
		copy(th[20:], opts)
		for i := 20 + len(opts); i < tcpHdrLen; i++ {
			th[i] = 0x01 // TCP NOP option
		}
	}
	copy(pkt[20+tcpHdrLen:], hello)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]))
	return pkt
}

// fakePacket builds the IPv4+TCP+payload packet of one fake ClientHello without TCP options. Pure: the same inputs
// build the same packet, so the tests pin it byte for byte (seq arithmetic, TTL, ack, checksum).
func fakePacket(k desyncKey, seq, ack uint32, ttl int, hello []byte) []byte {
	return fakePacketWithOptions(k, seq, ack, ttl, hello, nil)
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
	binary.BigEndian.PutUint16(pkt[10:], csum(pkt[:20]))
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
	snis      []string // SNIs with a non-empty hello; pickHello rebuilds fresh bytes per fire
	helloIdx  atomic.Uint32
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
	tcpOpts   []byte // kernel TCP options observed on outbound non-SYN segments (e.g. timestamps)
	at        time.Time
}

// newDesyncTracker prepares the state machine for one peer IP. Only SNIs that produce a hello are
// kept; pickHello rebuilds the hello per fire from these.
func newDesyncTracker(cfg DesyncConfig, peerIP [4]byte) *desyncTracker {
	snis := splitSNIs(cfg.SNI)
	good := make([]string, 0, len(snis))
	var hello []byte
	for _, s := range snis {
		if h := FakeClientHello(s); len(h) > 0 {
			good = append(good, s)
			if hello == nil {
				hello = h
			}
		}
	}
	return &desyncTracker{cfg: cfg, peerIP: peerIP, hello: hello, snis: good,
		conns: map[desyncKey]*desyncConn{}, wait: map[desyncKey]chan struct{}{}}
}

// pickHello builds a FRESH FakeClientHello per fire (round-robining the SNIs when several are
// configured). A cached hello replays byte-identical randoms (client random, session id, key share,
// ECH) on every connection from this process — two connections from one IP then carry matching
// synthetic hellos, a one-glance censor signature (audit 2026-10-21). FakeClientHello is ~1 µs.
func (t *desyncTracker) pickHello() []byte {
	if len(t.snis) == 0 {
		return t.hello
	}
	s := t.snis[0]
	if len(t.snis) > 1 {
		s = t.snis[int(t.helloIdx.Add(1)-1)%len(t.snis)]
	}
	if h := FakeClientHello(s); len(h) > 0 {
		return h
	}
	return t.hello
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
	now := time.Now()
	if len(t.conns) > 16 {
		for ck, c := range t.conns {
			if now.Sub(c.at) > 30*time.Second {
				t.abandonLocked(ck)
			}
		}
	}
	t.wait[k] = ch
	t.conns[k] = &desyncConn{synSeq: isn, isnKnown: known, at: now}
	return ch
}

// abandonLocked drops a connection (caller holds t.mu).
func (t *desyncTracker) abandonLocked(k desyncKey) {
	if ch := t.wait[k]; ch != nil {
		delete(t.wait, k)
		close(ch)
	}
	delete(t.conns, k)
}

// abandon drops a connection whose Wrap timed out (handshake never observed).
func (t *desyncTracker) abandon(k desyncKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.abandonLocked(k)
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
		if t.conns[out] != nil {
			t.abandonLocked(out)
		}
		if t.conns[in] != nil {
			t.abandonLocked(in)
		}
		return
	}
	// outbound non-SYN segment on a tracked connection: record kernel options (e.g. TCP timestamps)
	if c := t.conns[out]; c != nil && !syn && off > 20 && len(c.tcpOpts) == 0 {
		c.tcpOpts = append([]byte(nil), th[20:off]...)
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
				c.sumSeq = c.synSeq + 1
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
		hello := t.pickHello()
		if t.cfg.Mode == "seqsum" {
			// dual marker (2.8.0): the below-window seq fake first, then the in-window bad-checksum mirror
			// ~1 ms later (GoodbyeDPI sends wrong-seq + wrong-chksum as two fakes per connection). A filter
			// must discard BOTH correctly to miss the SNI: window-junk dropping alone does not stop the sum
			// marker, checksum dropping alone does not stop the seq marker. Both still die before the server.
			t.send(fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts))
			pkt := fakePacketWithOptions(k, base, ack, ttl, hello, c.tcpOpts)
			damageChecksum(pkt)
			// the second marker goes out after the 1 ms gap WITHOUT sleeping under t.mu: fireLocked runs
			// inside the sniffer's lock and a sleep here stalls every concurrent fire and Wrap announce
			// (audit 2026-10-21). close() never nils t.send, so a fire racing shutdown is a dropped packet.
			time.AfterFunc(time.Millisecond, func() { t.send(pkt) })
			return
		}
		if t.cfg.Mode == "sum" {
			// sum mode mirrors the triggering data segment: in-window seq (base = c.sumSeq), damaged checksum
			pkt := fakePacketWithOptions(k, base, ack, ttl, hello, c.tcpOpts)
			damageChecksum(pkt)
			t.send(pkt)
			return
		}
		pkt := fakePacketWithOptions(k, base-uint32(len(hello)), ack, ttl, hello, c.tcpOpts)
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
