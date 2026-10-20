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
// Verdict table (connAlive after the probes, and which marker correlated with a flow death):
//
//	conn alive                                     -> filter does not act on the markers: seq (the default)
//	conn died while a seq marker was in flight     -> filter drops below-window junk: sum
//	conn died only with the sum marker in flight   -> filter validates window+checksum: seqsum
//	probe socket never became writable             -> the path is fully blocked, no mode helps: seq anyway
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
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil || port == "" {
		note("probe: need an IPv4 host:port peer, keeping fake-mode seq")
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

// note is a package-level log line the tests can silence; it keeps probe.go free of a logf thread.
var note = func(format string, args ...any) {}

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

	// step 2: a sum-style marker next to the same flow. The tracker does not fire it for us (the probe's
	// tracker is in seq mode), so craft it here: an in-window duplicate of a small real write.
	p.sumOK = p.sumProbe(tc)

	// step 3: is the flow still alive after both?
	p.alive = p.connAlive(tc)
	switch {
	case !p.alive && !p.seqOK && p.sumOK:
		return "sum" // died with seq marker in flight but sum survived: filter drops below-window junk -> use sum
	case !p.alive && p.seqOK && !p.sumOK:
		return "seq" // died with sum marker in flight: filter drops bad checksums -> keep seq
	case !p.alive && !p.seqOK && !p.sumOK:
		return "seqsum" // died under both individual checks -> try seqsum
	default:
		return "seq"
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
	if !ok1 || !ok2 || la.IP.To4() == nil || ra.IP.To4() == nil {
		return true
	}
	hello := FakeClientHello(p.cfg.SNI)
	if hello == nil {
		return true
	}
	// read the socket's SND.NXT for the mirror base, exactly like Wrap's early path (needs CAP_NET_ADMIN;
	// without it the sum marker cannot be placed, and the verdict degrades to seq)
	isn, ok := isnOf(c)
	if !ok {
		return true // unknown: cannot place the marker, treat sum as tolerated rather than guess
	}
	var s, d [4]byte
	copy(s[:], la.IP.To4())
	copy(d[:], ra.IP.To4())
	k := desyncKey{s, d, uint16(la.Port), uint16(ra.Port)}
	pkt := fakePacket(k, isn, 0, 64, hello)
	damageChecksum(pkt)
	sendRawProbe(pkt)
	// the flow surviving the marker is the signal; the marker's ack=0 is wrong on purpose — the filter's
	// reassembler does not check it, and the server kernel never accepts the packet (bad checksum).
	if !p.connAlive(c) {
		return false
	}
	return true
}

// sendRawProbe sends one crafted IPv4 packet through the same throwaway IPPROTO_RAW socket the injector
// uses (IP_HDRINCL). Separate function so probe.go compiles on every OS with a stub elsewhere.
func sendRawProbe(pkt []byte) { sendRawPacket(pkt) }

// isnOf: the probe's one Linux socket dependency beyond NewDesync. On other OSes the probe never gets
// this far (NewDesync fails with the platform error), so the stub only exists for compilation.
func isnOf(c *net.TCPConn) (uint32, bool) { return tcpStreamBase(c) }
