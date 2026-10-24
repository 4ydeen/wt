package wat

// Filter probe (-fake-mode auto, 2.9.0): before the first pool dial the client measures WHICH marker class
// the path's filter tolerates, and the result picks the fake-SNI mode. Client only; the server never sees
// any of it. RESEARCH.md's queue item: a probe, then an auto-picked mode, instead of five questions.
//
// Method, on ONE throwaway TCP connection to the peer (not a pool slot):
//
//	1. Complete a normal handshake. The sniffer reports whether the seq marker fired (ISN probe + wire).
//	2. Fire a sum-style marker manually next to that connection (same seq/ack as a real data segment we
//	   then write; the filter sees an in-window duplicate with a bad checksum).
//	3. Write one byte of stream data and try to read the echo (the wattun server's target-port 0 answers,
//	   but ANY listening TCP service answers TCP at least with RST/ACK or data). If the connection still
//	   carries data a moment later, the filter did not reset the flow for the marker.
//
// Verdict table (which marker correlated with a flow death; the signal is the marker, not the final
// connAlive, whose failure only mirrors the last probe that ran on that socket):
//
//	seq marker survived, sum marker survived  -> filter ignores both markers: seq (the default)
//	seq marker killed its flow, sum survived  -> filter acts on below-window junk but ignores checksum junk: sum
//	both single markers killed their flows    -> filter acts on both: seqsum (the dual marker, last resort)
//	sum marker killed its flow, seq survived  -> filter acts on bad checksums but drops below-window junk: seq
//	probe socket never became writable        -> the path is fully blocked, no mode helps: seq anyway
//
// The probe runs once per process, logs its verdict, and exposes it through /stats (FilterProfile()).
// A failure anywhere degrades to seq (the 2.7.0 default) without stopping the tunnel.

import (
	"net"
	"sync"
	"time"
)

// FilterProfile is the startup probe's verdict, for /stats and the manager.
type FilterProfile struct {
	Mode      string `json:"mode"`       // the fake-mode the probe picked: seq|sum|seqsum
	SeqOK     bool   `json:"seq_ok"`     // the below-window seq marker did not kill the flow
	SumOK     bool   `json:"sum_ok"`     // the bad-checksum in-window marker did not kill the flow
	ConnAlive bool   `json:"conn_alive"` // the probe connection still carried data afterwards
	Probed    bool   `json:"probed"`     // a probe ran at all (false = disabled, off-platform, or it failed)
}

var (
	filterMu      sync.Mutex
	filterProfile = FilterProfile{Mode: "seq"}
)

// FilterProfileNow reports the startup probe's verdict (the zero value says no probe ran).
func FilterProfileNow() FilterProfile {
	filterMu.Lock()
	defer filterMu.Unlock()
	return filterProfile
}

// probeTimeout bounds each step; the whole probe adds at most ~3 s to startup, once.
const probeTimeout = 1500 * time.Millisecond

// ProbeFakeMode runs the marker probe against peer (host:port) with the allowlisted name and returns the
// mode to run fake-SNI with. called by cmd/wattun when -fake-mode auto. Needs the desync sniffer already
// running (it watches the probe handshake like any pool dial); on platforms without it the answer is seq.
func ProbeFakeMode(cfg DesyncConfig, peer string, logf func(string, ...any)) string {
	mode := "seq"
	ipStr, port := desyncPeerHostPort(peer)
	if net.ParseIP(ipStr) == nil || port == "" {
		note("probe: need an IP host:port peer, keeping fake-mode seq")
		return mode
	}
	var d *Desync
	var err error
	if d, err = NewDesync(DesyncConfig{SNI: cfg.SNI, Mode: "seq", TTL: cfg.TTL}, peer); err != nil {
		note("probe: no raw socket (%v), keeping fake-mode seq", err)
		return mode
	}
	defer d.Close()
	p := filterProbe{cfg: cfg, peer: peer, d: d, logf: logf}
	mode = p.run()
	filterMu.Lock()
	filterProfile = FilterProfile{Mode: mode, SeqOK: p.seqOK, SumOK: p.sumOK, ConnAlive: p.alive, Probed: true}
	filterMu.Unlock()
	if logf != nil {
		logf("fake-mode auto: probe says %q (seq_ok=%v sum_ok=%v conn_alive=%v)", mode, p.seqOK, p.sumOK, p.alive)
	}
	return mode
}

// note is the package-level log line of the fake-SNI layer (raw-send failures, the probe's fallbacks); it keeps
// probe.go free of a logf thread. It is silent until SetNote wires it, which cmd/wattun does at startup.
var note = func(format string, args ...any) {}

// SetNote routes the fake-SNI layer's one-time warnings to logf. Call it once, before NewDesync.
func SetNote(logf func(format string, args ...any)) {
	if logf != nil {
		note = logf
	}
}

// RawSendFails is how many fake-SNI fires could not be injected (raw socket open/bind/send failure).
// A rising counter with healthy tunnels means the real SNI is going out unprotected: switch carrier.
func RawSendFails() uint64 { return rawSendFails.Load() }

type filterProbe struct {
	cfg  DesyncConfig
	peer string
	d    *Desync
	logf func(string, ...any)

	seqOK, sumOK, alive bool
}

func (p *filterProbe) run() string {
	var nc net.Conn
	var err error
	nc, err = net.DialTimeout("tcp4", p.peer, probeTimeout)
	if err != nil {
		return "seq" // peer unreachable: every mode is moot, the tunnel would fail regardless
	}
	defer nc.Close()
	tc := nc.(*net.TCPConn)
	_ = tc.SetDeadline(time.Now().Add(probeTimeout))

	// step 1: the handshake plus the seq marker fire through the sniffer (Wrap waits for the fire)
	if _, err := p.d.Wrap(tc); err != nil {
		return "seq"
	}
	p.seqOK = p.connAlive(tc)

	// step 2: if tc was killed by the seq marker, open a fresh connection to test sum independently!
	targetConn := tc
	if !p.seqOK {
		_ = tc.Close()
		nc2, err := net.DialTimeout("tcp4", p.peer, probeTimeout)
		if err != nil {
			return "seq"
		}
		defer nc2.Close()
		targetConn = nc2.(*net.TCPConn)
		_ = targetConn.SetDeadline(time.Now().Add(probeTimeout))
	}

	p.sumOK = p.sumProbe(targetConn)

	// step 3: is the flow still alive after both? (kept for the log below; the verdict keys on which
	// marker killed its flow, because sumOK already implies its socket was alive after the sum probe)
	p.alive = p.connAlive(targetConn)
	switch {
	case !p.seqOK && p.sumOK:
		return "sum" // the seq marker killed its flow, the sum marker survived: the filter acts on below-window junk
	case !p.seqOK && !p.sumOK:
		return "seqsum" // both single markers correlate with a death: try the dual marker
	default:
		return "seq" // sum killed while seq survived (checksum validation), or nothing acted: keep seq
	}
}

// connAlive: after the probe writes, can we still push data and read anything back within the deadline?
// A censor reset lands within a packet RTT or two; a surviving flow accepts writes without error.
func (p *filterProbe) connAlive(c *net.TCPConn) bool {
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x00}); err != nil { // a tiny TLS-ish record
		return false // write error: the flow was reset (or the peer closed) after the marker
	}
	buf := make([]byte, 64)
	_, _ = c.Read(buf) // any answer (even RST->EOF) within the deadline: the kernel accepted more writes
	// a second write AFTER a possible RST is the real test: a reset flow now fails
	if _, err := c.Write([]byte{0x00}); err != nil {
		return false
	}
	return true
}

// sumProbe fires one bad-checksum in-window marker via the tracker's own packet builder, then watches the
// flow: seq/ack mirror the small real write that follows, like sum mode does with the first data segment.
func (p *filterProbe) sumProbe(c *net.TCPConn) bool {
	la, ok1 := c.LocalAddr().(*net.TCPAddr)
	ra, ok2 := c.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return true
	}
	s, sok := ipAddrOf(la.IP)
	d, dok := ipAddrOf(ra.IP)
	if !sok || !dok {
		return true
	}
	snis := splitSNIs(p.cfg.SNI)
	if len(snis) == 0 {
		return true
	}
	hello := FakeClientHello(snis[0])
	if hello == nil {
		return true
	}
	// read the socket's SND.NXT for the mirror base, exactly like Wrap's early path (needs CAP_NET_ADMIN;
	// without it the sum marker cannot be placed, and the verdict degrades to seq)
	isn, ok := isnOf(c)
	if !ok {
		return true // unknown: cannot place the marker, treat sum as tolerated rather than guess
	}
	k := desyncKey{s, d, uint16(la.Port), uint16(ra.Port)}
	ttl := 64
	if pt := p.d.PeerTTL(); pt > 0 { // the learned inbound TTL: the marker must mirror the production fire
		ttl = pt
	}
	pkt := fakePacket(k, isn, 0, ttl, hello)
	damageChecksum(pkt)
	sendRawProbe(pkt)
	// the flow surviving the marker is the signal; the marker's ack=0 is wrong on purpose — the filter's
	// reassembler does not check it, and the server kernel never accepts the packet (bad checksum).
	if !p.connAlive(c) {
		return false
	}
	return true
}

// sendRawProbe sends one crafted IPv4 or IPv6 packet through the same throwaway IPPROTO_RAW socket the injector
// uses (HDRINCL). Separate function so probe.go compiles on every OS with a stub elsewhere.
func sendRawProbe(pkt []byte) { sendRawPacket(pkt) }

// isnOf: the probe's one Linux socket dependency beyond NewDesync. On other OSes the probe never gets
// this far (NewDesync fails with the platform error), so the stub only exists for compilation.
func isnOf(c *net.TCPConn) (uint32, bool) { nxt, _, ok := tcpStreamBase(c); return nxt, ok }
