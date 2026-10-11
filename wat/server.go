package wat

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RawIO is the server's view of the wire: every client's datagrams arrive on one socket.
type RawIO interface {
	Recv() (p []byte, lane int, src net.Addr, err error)
	SendTo(p []byte, lane int, dst net.Addr) error
	Close() error
}

type rxPkt struct {
	p    []byte
	lane int
	src  net.Addr
}

// Server demultiplexes one raw socket into independent client Sessions, keyed by the session id each client
// process picks at start. Two clients on one key (the two slots of a handover, a restart loop) never touch each
// other, and a server instance that is draining accepts no new sessions while it finishes the ones it has.
type Server struct {
	cfg      Config
	raw      RawIO
	mu       sync.Mutex
	sessions map[uint64]*srvSess
	New      chan *Session // freshly authenticated client sessions
	draining atomic.Bool
	stop     chan struct{}
	closed   bool
	free     chan []byte // receive buffers for the sessions' inboxes

	MaxSessions int
	IdleTimeout time.Duration

	lastRx atomic.Int64 // unix nanoseconds of the newest authenticated packet of any session, kept after it closes

	statMu  sync.Mutex
	seen    map[*Session]Stats // each live session's counters at the last Stats call
	retired Stats              // counters of sessions that have closed, so the totals never go backwards
}

type srvSess struct {
	s    *Session
	io   *subIO
	last atomic.Int64 // unix nanoseconds of the last packet
}

type subIO struct {
	srv   *Server
	prev  []byte // the datagram the last Recv returned: handed back to the server pool on the next call
	sid   uint64
	inbox chan rxPkt
	peer  atomic.Value // net.Addr
	done  chan struct{}
	once  sync.Once
}

func (b *subIO) Send(p []byte, lane int) error {
	v := b.peer.Load()
	if v == nil {
		return errors.New("wat: no peer yet")
	}
	return b.srv.raw.SendTo(p, lane, v.(net.Addr))
}

func (b *subIO) Recv() ([]byte, int, net.Addr, error) {
	if b.prev != nil {
		b.srv.putBuf(b.prev)
		b.prev = nil
	}
	select {
	case r := <-b.inbox:
		b.prev = r.p
		return r.p, r.lane, r.src, nil
	case <-b.done:
		return nil, 0, nil, errors.New("wat: session closed")
	}
}

// CopiesOnSend: the session may reuse a datagram buffer after Send when the shared socket copies it (raw ICMP, UDP).
func (b *subIO) CopiesOnSend() bool { return copies(b.srv.raw) }

func (b *subIO) Profile() Profile { return profileOf(b.srv.raw) }

func (b *subIO) SetPeer(a net.Addr) {
	if a != nil {
		b.peer.Store(a)
	}
}

func (b *subIO) Close() error {
	b.once.Do(func() {
		close(b.done)
		b.srv.mu.Lock()
		ss := b.srv.sessions[b.sid]
		delete(b.srv.sessions, b.sid)
		b.srv.mu.Unlock()
		if ss != nil { // keep Server.LastRecv monotonic: the session no longer feeds it once it leaves the map
			b.srv.noteRecv(ss.s.LastRecv())
		}
	})
	return nil
}

func NewServer(cfg Config, raw RawIO) *Server {
	cfg.Server = true
	if cfg.Boot == 0 {
		var b [8]byte
		crand.Read(b[:])
		cfg.Boot = binary.BigEndian.Uint64(b[:]) | 1
	}
	srv := &Server{cfg: cfg, raw: raw, sessions: map[uint64]*srvSess{}, New: make(chan *Session, 64),
		stop: make(chan struct{}), free: make(chan []byte, 1024), MaxSessions: 32, IdleTimeout: 45 * time.Second}
	go srv.run()
	go srv.janitor()
	return srv
}

// Drain stops accepting new sessions; existing ones continue until they end.
func (srv *Server) Drain() { srv.draining.Store(true) }

func (srv *Server) Draining() bool { return srv.draining.Load() }

func (srv *Server) Sessions() int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.sessions)
}

func (srv *Server) Stats() Stats {
	srv.mu.Lock()
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	srv.statMu.Lock()
	defer srv.statMu.Unlock()
	now := make(map[*Session]Stats, len(list))
	var t Stats
	for _, s := range list {
		st := s.Stats()
		t.PktsOut += st.PktsOut
		t.PktsIn += st.PktsIn
		t.BytesOut += st.BytesOut
		t.BytesIn += st.BytesIn
		t.Retrans += st.Retrans
		t.Dropped += st.Dropped
		t.RateBps += st.RateBps
		t.Streams += st.Streams
		t.Inflight += st.Inflight
		t.FecSent += st.FecSent
		t.FecRecovered += st.FecRecovered
		t.CeilingBps += st.CeilingBps
		if st.LossPct > t.LossPct {
			t.LossPct = st.LossPct
		}
		if st.SRTT > t.SRTT {
			t.SRTT = st.SRTT
		}
		if t.MinRTT == 0 || (st.MinRTT > 0 && st.MinRTT < t.MinRTT) {
			t.MinRTT = st.MinRTT
		}
		now[s] = st
	}
	// A closed session leaves the map; keep its last counters so the cumulative totals stay monotonic (callers
	// subtract the previous total, and a smaller total wrapped to ~1.8e19 in the stats log).
	for s, st := range srv.seen {
		if _, live := now[s]; !live {
			addCounters(&srv.retired, st)
		}
	}
	srv.seen = now
	addCounters(&t, srv.retired)
	return t
}

// ClientInfo describes one live client session.
type ClientInfo struct {
	IP      string // the session's current peer source IP, no port
	Carrier string // carrier it was last heard on (MultiRaw servers only, else empty)
	Age     time.Duration
}

// Clients lists the live client sessions. Cheap enough for a stats endpoint.
func (srv *Server) Clients() []ClientInfo {
	mr, _ := srv.raw.(*MultiRaw)
	now := time.Now()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	out := make([]ClientInfo, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		var ci ClientInfo
		if lr := ss.s.LastRecv(); !lr.IsZero() {
			ci.Age = max(now.Sub(lr), 0)
		} else {
			ci.Age = max(now.Sub(time.Unix(0, ss.last.Load())), 0)
		}
		a, _ := ss.io.peer.Load().(net.Addr)
		if t, ok := a.(*TaggedAddr); ok {
			a = t.Addr
			if mr != nil && t.Idx >= 0 && t.Idx < len(mr.names) {
				ci.Carrier = mr.names[t.Idx]
			}
		}
		ci.IP = addrIP(a)
		out = append(out, ci)
	}
	return out
}

func addrIP(a net.Addr) string {
	switch v := a.(type) {
	case nil:
		return ""
	case poolAddr:
		return v.ip
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

// LastRecv is when the newest authenticated packet from any client arrived, including sessions that have closed
// since the server started (zero: none yet).
func (srv *Server) LastRecv() time.Time {
	srv.mu.Lock()
	for _, ss := range srv.sessions {
		srv.noteRecv(ss.s.LastRecv())
	}
	srv.mu.Unlock()
	if n := srv.lastRx.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (srv *Server) noteRecv(t time.Time) {
	if t.IsZero() {
		return
	}
	for n := t.UnixNano(); ; {
		old := srv.lastRx.Load()
		if n <= old || srv.lastRx.CompareAndSwap(old, n) {
			return
		}
	}
}

// addCounters adds the cumulative counters of b to a (not the rates, RTTs or live gauges).
func addCounters(a *Stats, b Stats) {
	a.PktsOut += b.PktsOut
	a.PktsIn += b.PktsIn
	a.BytesOut += b.BytesOut
	a.BytesIn += b.BytesIn
	a.Retrans += b.Retrans
	a.Dropped += b.Dropped
	a.FecSent += b.FecSent
	a.FecRecovered += b.FecRecovered
}

// CarrierStats sums the per-carrier numbers of every client session (nil unless the server runs on a MultiRaw).
func (srv *Server) CarrierStats() []CarrierStat {
	if _, ok := srv.raw.(*MultiRaw); !ok {
		return nil
	}
	srv.mu.Lock()
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	var out []CarrierStat
	n := make([]int, 0)
	for _, s := range list {
		for i, c := range s.CarrierStats() {
			for len(out) <= i {
				out = append(out, CarrierStat{})
				n = append(n, 0)
			}
			o := &out[i]
			o.Name, o.Sent, o.Acked, o.Lost = c.Name, o.Sent+c.Sent, o.Acked+c.Acked, o.Lost+c.Lost
			o.Alive = o.Alive || c.Alive
			if c.Present {
				n[i]++
				o.Share += c.Share
				if o.SRTTms == 0 || c.SRTTms > 0 && c.SRTTms < o.SRTTms {
					o.SRTTms = c.SRTTms
				}
			}
		}
	}
	for i := range out {
		if n[i] > 0 {
			out[i].Share /= float64(n[i])
		}
	}
	return out
}

func (srv *Server) Close() {
	srv.mu.Lock()
	if srv.closed {
		srv.mu.Unlock()
		return
	}
	srv.closed = true
	close(srv.stop)
	list := make([]*Session, 0, len(srv.sessions))
	for _, ss := range srv.sessions {
		list = append(list, ss.s)
	}
	srv.mu.Unlock()
	for _, s := range list {
		s.Close()
	}
	srv.raw.Close()
}

func (srv *Server) run() {
	var bo recvBackoff
	for {
		p, lane, src, err := srv.raw.Recv()
		if err != nil {
			select {
			case <-srv.stop:
				return
			default:
				bo.fail(err, srv.cfg.Logf, "server receive")
				continue
			}
		}
		bo.ok()
		if len(p) < hdrLen+tagLen+1 {
			continue
		}
		if binary.BigEndian.Uint64(p[8:])&dirServerBit != 0 {
			// Our own packet coming back: in reverse ICMP the client host's kernel answers every request with a copy.
			// It carries a live session id, so counting it as traffic would keep a dead client's session from ever
			// going idle. The session would drop it anyway (own direction).
			continue
		}
		sid := binary.BigEndian.Uint64(p)
		srv.mu.Lock()
		ss := srv.sessions[sid]
		srv.mu.Unlock()
		if ss == nil {
			if srv.draining.Load() {
				continue
			}
			ss = srv.admit(sid, p)
			if ss == nil {
				continue
			}
		}
		ss.last.Store(time.Now().UnixNano())
		select {
		case ss.io.inbox <- rxPkt{srv.getBuf(p), lane, src}:
		default: // overloaded: a dropped datagram is just loss
		}
	}
}

// admit creates a session for an unknown id, but only if this very packet authenticates under that id's key.
func (srv *Server) admit(sid uint64, p []byte) *srvSess {
	pn := binary.BigEndian.Uint64(p[8:])
	if pn&dirServerBit != 0 {
		return nil
	}
	aead, err := sessionAEAD(srv.cfg.Key, sid)
	if err != nil {
		return nil
	}
	var nonce [12]byte
	copy(nonce[4:], p[8:16])
	if _, err := aead.Open(nil, nonce[:], p[hdrLen:], p[:8]); err != nil {
		return nil
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.sessions) >= srv.MaxSessions || srv.closed {
		return nil
	}
	if ss := srv.sessions[sid]; ss != nil {
		return ss
	}
	io := &subIO{srv: srv, sid: sid, inbox: make(chan rxPkt, 8192), done: make(chan struct{})}
	cfg := srv.cfg
	cfg.SID = sid
	var pio PacketIO = io
	if mr, ok := srv.raw.(*MultiRaw); ok { // bonded server: reply on the best live carrier of this client
		pio = newMultiSubIO(io, mr, cfg.Bond)
	}
	s, err := NewSession(cfg, pio)
	if err != nil {
		return nil
	}
	ss := &srvSess{s: s, io: io}
	ss.last.Store(time.Now().UnixNano())
	srv.sessions[sid] = ss
	select {
	case srv.New <- s:
	default:
		go func() { srv.New <- s }()
	}
	if srv.cfg.Logf != nil {
		srv.cfg.Logf("new client session %016x (%d active)", sid, len(srv.sessions))
	}
	return ss
}

func (srv *Server) janitor() {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-srv.stop:
			return
		case <-tk.C:
			var dead []*Session
			cut := time.Now().Add(-srv.IdleTimeout).UnixNano()
			srv.mu.Lock()
			for _, ss := range srv.sessions {
				if ss.last.Load() < cut {
					dead = append(dead, ss.s)
				}
			}
			srv.mu.Unlock()
			for _, s := range dead {
				srv.noteRecv(s.LastRecv())
				if srv.cfg.Logf != nil {
					srv.cfg.Logf("client session %016x idle, closing", s.sid)
				}
				s.Close()
			}
		}
	}
}

// getBuf copies a received datagram into a pooled buffer (the raw socket reuses its own buffer on the next Recv).
func (srv *Server) getBuf(p []byte) []byte {
	select {
	case b := <-srv.free:
		if cap(b) >= len(p) {
			return append(b[:0], p...)
		}
	default:
	}
	return append(make([]byte, 0, max(len(p), 2048)), p...)
}

func (srv *Server) putBuf(b []byte) {
	select {
	case srv.free <- b:
	default:
	}
}

// SendBatch forwards a burst to the shared socket in one call when it can (sendmmsg), else datagram by datagram.
// (A bonded session's multiSubIO embeds subIO but is a PathChooser, so the session never batches it.)
func (b *subIO) SendBatch(ps [][]byte, lanes []int) error {
	v := b.peer.Load()
	if v == nil {
		return errors.New("wat: no peer yet")
	}
	dst := v.(net.Addr)
	if rb, ok := b.srv.raw.(RawBatchSender); ok {
		return rb.SendBatchTo(ps, lanes, dst)
	}
	var first error
	for i, p := range ps {
		if err := b.srv.raw.SendTo(p, lanes[i], dst); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// recvBackoff paces a receive loop whose Recv keeps failing: 1 ms doubling to 200 ms, reset by a good Recv. The
// first error of a streak is logged once. The no-error path costs one bool test.
type recvBackoff struct {
	d      time.Duration
	failed bool
}

func (b *recvBackoff) fail(err error, logf func(string, ...any), what string) {
	if !b.failed {
		b.failed = true
		if logf != nil {
			logf("%s error (retrying with backoff): %v", what, err)
		}
	}
	if b.d == 0 {
		b.d = time.Millisecond
	}
	time.Sleep(b.d)
	if b.d *= 2; b.d > 200*time.Millisecond {
		b.d = 200 * time.Millisecond
	}
}

func (b *recvBackoff) ok() {
	if b.failed {
		b.failed, b.d = false, 0
	}
}
