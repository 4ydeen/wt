// Package wat is WatTunnel: a multiplexed, encrypted, paced transport for paths that only pass ICMP echo.
package wat

import (
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxPayload   = 640 // default datagram size: ICMP echo payload cap, stays under the 680 route MTU after IP+ICMP headers
	MinPayload   = 256 // bounds of Config.MaxPayload
	MaxPayloadHi = 1400
	hdrLen       = 16 // session id (8) + explicit packet number (8); nonce = 4 zero bytes + pn
	tagLen       = 16
	overhead     = hdrLen + tagLen
	streamWindow = 4 << 20
	sendBufMax   = 4 << 20
	prioBytes    = 64 << 10 // streams that sent less than this go first (interactive traffic)
	dirServerBit = uint64(1) << 63
	replayWin    = 1024
	// A pool of TCP connections reorders by a whole head-of-line stall (60-100 ms of packets, ~1900 at 640 B and
	// 12 MB/s); a window of 1024 turned every late packet after a stall into a "replay" and dropped it (measured).
	reliableReplayWin = 16384
	maxStreams   = 8192
	ipIcmpHdr    = 28
)

var ErrSessionDead = errors.New("wat: session closed")

type Config struct {
	Server     bool
	Key        []byte
	SID        uint64        // session id (client: random if 0; server sessions get the client's)
	Paths      int           // client: lanes (ICMP identifiers) to stripe over
	InitBps    float64       // starting pace, bytes/s (default 1.5 MB/s)
	MaxBps     float64       // pace ceiling, bytes/s (default 16 MB/s)
	MinBps     float64       // pace floor (default 200 KB/s)
	Slack      time.Duration // extra RTT over the minimum tolerated before slowing down (default 8 ms)
	Boot       uint64        // server process id (random per run); clients reset their streams when it changes
	MaxPayload int           // datagram size cap incl. header and tag; 0 = MaxPayload (640), bounded to [256, 1400]
	Hedge      bool          // send young packets twice on different lanes (costs ~8% extra packets)
	FEC        bool          // adaptive XOR parity after bursts of small packets (both ends must enable it; see fec.go)
	Bond       PathTimings   // multipath health/probe timings (server side; zero = production values)
	Logf       func(string, ...any)
}

type Stats struct {
	PktsOut, PktsIn, BytesOut, BytesIn uint64
	Retrans, Dropped                   uint64
	RateBps                            float64
	SRTT, MinRTT                       time.Duration
	Streams                            int
	Inflight                           int
	// datagrams (UDP forwarding)
	DgramSent, DgramRecv                      uint64
	DgramDropQueue, DgramDropSize, DgramDropRx uint64
	FecSent, FecRecovered                      uint64
	CeilingBps, LossPct                        float64 // loss-aware soft ceiling (0 = none); last judged interval loss in percent
}

type sentPkt struct {
	pn     uint64
	at     time.Time
	size   int
	frames []frameRef
	ctrl   [][]byte
	dgram  bool // carries datagrams: tracked for pacing/inflight only, never retransmitted
	lane   int  // path it was sent on (the ICMP lane, or the bond path)
	done   bool // acked or declared lost
	lost   bool // declared lost (bond: a late ack still proves the path alive)
}

type outPkt struct {
	p       []byte
	lane    int
	dupLane int // >=0: send the identical datagram again on this lane (hedge against random loss)
}

type Session struct {
	cfg  Config
	sid  uint64
	io   PacketIO
	aead cipher.AEAD
	mu   sync.Mutex
	now  time.Time

	closed   bool
	stop     chan struct{}
	nextPN   uint64
	laneRR   int
	laneSeen map[int]time.Time
	lanes    []int

	// receive state
	rxAny     bool
	rxLargest uint64
	rxRing    []uint64 // replay window: 1024 packets, or reliableReplayWin for a Profile.Reliable carrier
	replayWin uint64
	ackMax    int // SACK ranges per ACK frame (the wire format allows 64)
	rxKeep    int // received ranges remembered
	rxRanges  rangeSet
	rxAt      time.Time
	ackPend   int
	ackSince  time.Time
	lastRecv  time.Time // cleared after 30 s of silence (the session then counts as dead)
	lastAuth  time.Time // same, never cleared: what LastRecv reports

	streams  map[uint64]*Stream
	tomb     map[uint64]time.Time
	nextSID  uint64
	acceptQ  []*Stream
	acceptC  *sync.Cond
	prio     streamQ // interactive streams (sent < prioBytes), FIFO
	bulk     fairQ   // bulk streams: fair between groups (public ports), round-robin inside a group
	ctrl     [][]byte
	sent     []*sentPkt
	sentHead int
	inflight int
	cc       cc
	lastSend time.Time
	wantPing bool
	stats    Stats
	openBuf  []byte
	winSlack uint64 // bytes a peer's largest datagram may overshoot the advertised stream window
	maxPlain int    // plaintext bytes per datagram: cfg.MaxPayload - header - tag
	plainBuf []byte // reused packet assembly buffer (nextPacket runs under s.mu)
	txNonce  [12]byte // seal runs under s.mu; kept here because an array passed to the AEAD interface escapes to the heap
	rxNonce  [12]byte // handle runs on the receive goroutine only
	copier   bool     // the carrier copies a datagram inside Send, so the buffer may be reused as soon as Send returns
	outFree  chan []byte
	batcher  BatchSender // nil: send one datagram at a time
	bp       [][]byte
	bl       []int
	spFree   []*sentPkt
	ackRs    []rng // parsed ACK ranges, valid for one parse

	fec      *fecState // nil unless Config.FEC
	hedgeTok float64 // bytes of hedging allowed: ~8% of what was sent
	bootAt   time.Time
	peerBoot uint64
	wake     chan struct{}

	dq      [][]byte // encoded frDgram frames waiting to go out (unreliable, bounded)
	dqBytes int
	dgIn    chan Datagram
	dbuf    []byte // scratch: datagram frames chosen for the packet being built

	// multipath (nil/empty for every single-carrier PacketIO)
	chooser PathChooser
	fb      PathFeedback
	pcc     []pathCC
	probeQ  []int
	ackBuf  []*sentPkt
	smpBuf  []*sentPkt
}

// pathCC is the session's own per-path delay/ordering state, used only with a PathChooser: loss detection must
// compare a packet with later packets of ITS path (paths of different delay reorder against each other), and the
// pacer must see queueing growth on a path, not the difference between two paths.
type pathCC struct {
	srtt, minRTT time.Duration
	minAt, at    time.Time
	largest      uint64
	have         bool
	reliable     bool
	ackOnly      int // ack-only packets since the last PING on this path
}

func NewSession(cfg Config, pio PacketIO) (*Session, error) {
	if cfg.Paths <= 0 {
		cfg.Paths = 1
	}
	prof := profileOf(pio)
	if cfg.InitBps == 0 {
		cfg.InitBps = 1.5e6
		if prof.InitBps > 0 {
			cfg.InitBps = prof.InitBps
		}
	}
	if cfg.MaxBps == 0 {
		cfg.MaxBps = 16e6
	}
	if cfg.MinBps == 0 {
		cfg.MinBps = 2e5
	}
	if cfg.Slack == 0 {
		cfg.Slack = 8 * time.Millisecond
	}
	hi := MaxPayloadHi
	if prof.MaxMTU > hi {
		hi = prof.MaxMTU
	}
	if cfg.MaxPayload == 0 {
		cfg.MaxPayload = MaxPayload
		if prof.MTU > 0 {
			cfg.MaxPayload = prof.MTU
		}
	}
	cfg.MaxPayload = min(max(cfg.MaxPayload, MinPayload), hi)
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.SID == 0 {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			return nil, err
		}
		cfg.SID = binary.BigEndian.Uint64(b[:]) | 1
	}
	aead, err := sessionAEAD(cfg.Key, cfg.SID)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg: cfg, sid: cfg.SID, io: pio, aead: aead, stop: make(chan struct{}),
		laneSeen: map[int]time.Time{}, streams: map[uint64]*Stream{}, tomb: map[uint64]time.Time{},
		nextSID: 1, now: time.Now(), wake: make(chan struct{}, 1),
		cc:       newCC(cfg.InitBps, cfg.MinBps, cfg.MaxBps, cfg.Slack),
		maxPlain: cfg.MaxPayload - overhead,
		winSlack: uint64(hi - overhead),
	}
	s.cc.reliable = prof.Reliable
	s.replayWin, s.ackMax, s.rxKeep = replayWin, 20, 64
	if prof.Reliable { // pool reordering leaves a hole per stalled connection's packets: track and report more of them
		s.replayWin, s.ackMax, s.rxKeep = reliableReplayWin, 64, 512
	}
	if ch, ok := pio.(PathChooser); ok && ch.NumPaths() > 0 {
		s.replayWin = reliableReplayWin // paths of different delay put packets thousands of numbers behind each other
	}
	s.rxRing = make([]uint64, s.replayWin)
	if b, ok := pio.(BatchSender); ok && !isChooser(pio) && batchWanted(pio) {
		s.batcher = b // the multipath chooser has its own Send and never implements BatchSender
	}
	if copies(pio) {
		s.copier = true
		s.outFree = make(chan []byte, 512)
	}
	s.plainBuf = make([]byte, 0, s.maxPlain)
	s.dgIn = make(chan Datagram, dgramRxCap)
	if ch, ok := pio.(PathChooser); ok && ch.NumPaths() > 0 {
		s.chooser = ch
		s.pcc = make([]pathCC, ch.NumPaths())
		s.smpBuf = make([]*sentPkt, ch.NumPaths())
		for i := range s.pcc {
			s.pcc[i].reliable = ch.PathProfile(i).Reliable
		}
		s.ackMax, s.rxKeep = 64, 512 // two paths reorder and double the holes: report as many ranges as the wire allows
		s.fb, _ = pio.(PathFeedback)
		if pr, ok := pio.(PathProber); ok {
			pr.SetProber(s.probePath)
		}
	}
	s.cc.maxPlain = s.maxPlain
	if cfg.FEC {
		s.fec = newFec()
	}
	// A client run has its own random session id and with it its own key, so its packet numbers can start at 0 and two
	// clients on one key (two slots) are independent sessions. A restarted SERVER meets the same session id again, so
	// its packet numbers start at the wall clock in microseconds: a new run always continues above the old one (no
	// nonce reuse, and the client does not mistake the new packets for replays of the old ones).
	if cfg.Server {
		s.nextPN = dirServerBit | uint64(time.Now().UnixMicro())&(1<<62-1)
	}
	s.acceptC = sync.NewCond(&s.mu)
	if !cfg.Server {
		for i := 0; i < cfg.Paths; i++ {
			s.lanes = append(s.lanes, i)
		}
	}
	go s.recvLoop()
	go s.pump()
	return s, nil
}

// sessionAEAD derives the per-session key: the same PSK with another session id is a different key.
func sessionAEAD(key []byte, sid uint64) (cipher.AEAD, error) {
	h := sha256.New()
	h.Write([]byte("github.com/JohnWatsoon/WatTunnel/v2:"))
	h.Write(key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sid)
	h.Write(b[:])
	return chacha20poly1305.New(h.Sum(nil))
}

func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stop)
	for _, st := range s.streams {
		s.killStream(st, ErrSessionDead)
	}
	s.acceptC.Broadcast()
	s.mu.Unlock()
	s.io.Close()
}

func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.RateBps, st.SRTT, st.MinRTT = s.cc.rate, s.cc.srtt, s.cc.minRTT
	st.CeilingBps, st.LossPct = s.cc.ceiling, s.cc.lossPct*100
	st.Streams, st.Inflight = len(s.streams), s.inflight
	return st
}

// Load reports the open streams and the bytes in flight: what a client running several sessions (-sessions N)
// balances new streams on. Cheaper than Stats.
func (s *Session) Load() (streams, inflight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams), s.inflight
}

// OpenStream starts a new stream (client side).
func (s *Session) OpenStream() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionDead
	}
	if len(s.streams) >= maxStreams {
		return nil, ErrTooManyConns
	}
	id := s.nextSID
	s.nextSID++
	return s.newStream(id), nil
}

// Accept waits for a stream opened by the peer (server side).
func (s *Session) Accept() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.acceptQ) == 0 && !s.closed {
		s.acceptC.Wait()
	}
	if len(s.acceptQ) == 0 {
		return nil, ErrSessionDead
	}
	st := s.acceptQ[0]
	s.acceptQ = s.acceptQ[1:]
	return st, nil
}

func (s *Session) activate(st *Stream) {
	if st.inActive || st.dead || !st.sendable() {
		return
	}
	st.inActive = true
	s.enqueue(st)
	s.kick()
}

func (s *Session) enqueue(st *Stream) {
	if st.sentTotal < prioBytes {
		s.prio.push(st)
	} else {
		s.bulk.push(st)
	}
}

func (s *Session) pick() *Stream {
	for s.prio.len() > 0 {
		st := s.prio.pop()
		if st.dead || !st.sendable() {
			st.inActive = false
			continue
		}
		if st.sentTotal >= prioBytes {
			s.bulk.push(st)
			continue
		}
		return st
	}
	for s.bulk.n > 0 {
		st := s.bulk.pop()
		if st.dead || !st.sendable() {
			st.inActive = false
			continue
		}
		return st
	}
	return nil
}

func (s *Session) requeue(st *Stream) {
	if st.dead || !st.sendable() {
		st.inActive = false
		return
	}
	s.enqueue(st)
}

func (s *Session) hasWork() bool {
	return len(s.dq) > 0 || s.hasStreamWork()
}

func (s *Session) hasStreamWork() bool {
	work := func(st *Stream) bool { return !st.dead && st.sendable() }
	return s.prio.any(work) || s.bulk.any(work)
}

// ---- sending ----

// kick wakes the pump now: new data, a window update, or an ack-eliciting packet arrived.
func (s *Session) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// busy: anything the pump must act on soon. Idle sessions tick slowly (keepalives need ~2 s precision).
func (s *Session) busy() bool {
	return s.ackPend > 0 || len(s.ctrl) > 0 || s.wantPing || len(s.probeQ) > 0 || s.sentHead < len(s.sent) || s.prio.len() > 0 || s.bulk.n > 0 || len(s.dq) > 0 || (s.fec != nil && s.fec.txN > 0)
}

func (s *Session) pump() {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	last := time.Now()
	var batch []outPkt
	for {
		select {
		case <-s.stop:
			return
		case <-timer.C:
		case <-s.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		now := time.Now()
		dt := now.Sub(last)
		last = now
		s.mu.Lock()
		s.now = now
		s.cc.refill(dt)
		s.timers(now)
		batch = batch[:0]
		for len(batch) < 160 {
			o, ok := s.build(now)
			if !ok {
				break
			}
			batch = append(batch, o)
		}
		if s.fec != nil {
			if o, ok := s.fecDue(now); ok {
				batch = append(batch, o)
			}
		}
		next := 100 * time.Millisecond
		if s.busy() || len(batch) > 0 {
			next = time.Millisecond
		}
		s.mu.Unlock()
		if s.batcher != nil && len(batch) > 1 {
			s.sendBatch(batch)
		} else {
			s.sendEach(batch)
		}
		timer.Reset(next)
	}
}

func (s *Session) sendEach(batch []outPkt) {
	for _, o := range batch {
		if err := s.io.Send(o.p, o.lane); err != nil {
			s.mu.Lock()
			s.stats.Dropped++
			s.mu.Unlock()
		}
		if o.dupLane >= 0 {
			s.io.Send(o.p, o.dupLane)
		}
		s.putOut(o.p)
	}
}

// sendBatch hands everything the pacer released to the carrier in one call (sendmmsg on Linux).
func (s *Session) sendBatch(batch []outPkt) {
	ps, ls := s.bp[:0], s.bl[:0]
	for _, o := range batch {
		ps, ls = append(ps, o.p), append(ls, o.lane)
		if o.dupLane >= 0 {
			ps, ls = append(ps, o.p), append(ls, o.dupLane)
		}
	}
	if err := s.batcher.SendBatch(ps, ls); err != nil {
		s.mu.Lock()
		s.stats.Dropped++
		s.mu.Unlock()
	}
	for i, o := range batch {
		s.putOut(o.p)
		ps[i] = nil
	}
	clear(ps)
	s.bp, s.bl = ps[:0], ls[:0]
}

func (s *Session) nextLane() int {
	if len(s.lanes) == 0 {
		return -1
	}
	s.laneRR++
	return s.lanes[s.laneRR%len(s.lanes)]
}

func (s *Session) build(now time.Time) (outPkt, bool) {
	const none = -1
	if len(s.probeQ) > 0 {
		return s.buildProbe(now), true
	}
	needAck := s.ackPend > 0 && (s.ackPend >= 6 || now.Sub(s.ackSince) >= 2*time.Millisecond)
	canData := s.cc.tokens > 0 && s.inflight < s.cc.cwnd()
	needBoot := s.cfg.Server && s.cfg.Boot != 0 && now.Sub(s.bootAt) >= time.Second
	if !canData && !needAck && !s.wantPing && len(s.ctrl) == 0 && !needBoot {
		if s.hasWork() {
			s.cc.limited = true
		}
		return outPkt{}, false
	}
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	}
	prioSeen, bulkSeen := false, false
	p := s.plainBuf[:0]
	sp := s.newSent()
	if needBoot {
		p = append(p, frBoot)
		p = appendUv(p, s.cfg.Boot)
		s.bootAt = now
	}
	if needAck {
		delay := uint64(now.Sub(s.rxAt) / time.Microsecond)
		p = appendAck(p, s.rxRanges, delay, s.ackMax)
		s.ackPend = 0
	}
	for len(s.ctrl) > 0 && len(p)+len(s.ctrl[0]) <= s.maxPlain {
		p = append(p, s.ctrl[0]...)
		sp.ctrl = append(sp.ctrl, s.ctrl[0])
		s.ctrl = s.ctrl[1:]
	}
	if s.wantPing {
		p = append(p, frPing)
		s.wantPing = false
		sp.ctrl = append(sp.ctrl, pingFrame)
	}
	if canData {
		// Datagrams go before stream data (they are interactive), but as the LAST frames of the packet so an old
		// peer that stops at the unknown type still sees everything before it. While streams have work, datagrams
		// take at most half of what is left, so a datagram flood cannot starve a bulk transfer.
		dbuf := s.dbuf[:0]
		if len(s.dq) > 0 {
			dbuf = s.takeDgrams(dbuf, s.maxPlain-len(p), s.hasStreamWork())
			s.dbuf = dbuf[:0]
		}
		room := s.maxPlain - len(dbuf)
		for room-len(p) > 40 {
			st := s.pick()
			if st == nil {
				break
			}
			isBulk := st.sentTotal >= prioBytes
			if isBulk {
				bulkSeen = true
			} else {
				prioSeen = true
			}
			np, sent, fit := st.emit(p, sp, room-len(p))
			if isBulk {
				s.bulk.charge(st, len(np)-len(p))
			}
			p = np
			s.requeue(st)
			if !sent {
				if !fit {
					break
				}
				continue
			}
		}
		if len(dbuf) > 0 {
			p = append(p, dbuf...)
			sp.dgram = true
		}
		if len(sp.frames) == 0 && len(p) == 0 {
			s.freeSent(sp)
			return outPkt{}, false
		}
		if s.cc.tokens <= 0 || s.inflight >= s.cc.cwnd() {
			if s.hasWork() {
				s.cc.limited = true
			}
		}
	}
	if len(p) == 0 {
		s.freeSent(sp)
		return outPkt{}, false
	}
	if s.chooser != nil { // bond: packets that carry young streams, datagrams, acks or are small want the fastest path
		lane = s.chooser.ChoosePath(len(p)+overhead, prioSeen || !bulkSeen || len(p)+overhead <= 330)
		// An ack-only packet is never acked, so a path used only for acks (a download's return path) would give no
		// feedback and a dead one would go unnoticed: every 16th such packet on a path carries a PING.
		if len(sp.frames) == 0 && len(sp.ctrl) == 0 && !sp.dgram && lane >= 0 && lane < len(s.pcc) {
			pc := &s.pcc[lane]
			if pc.ackOnly++; pc.ackOnly >= 16 {
				pc.ackOnly = 0
				p = append(p, frPing)
				sp.ctrl = append(sp.ctrl, pingFrame)
			}
		}
	}
	out, pn := s.seal(p)
	size := len(out) + ipIcmpHdr
	if len(sp.frames) > 0 || len(sp.ctrl) > 0 || sp.dgram {
		if s.fec != nil && (len(sp.frames) > 0 || sp.dgram) {
			s.fecNoteSent(pn, p)
		}
		sp.pn, sp.at, sp.size, sp.lane = pn, now, size, lane
		s.sent = append(s.sent, sp)
		s.cc.sentN++
		s.inflight += size
		s.cc.tokens -= float64(size)
	} else {
		s.freeSent(sp) // ack-only: nothing to track
	}
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	dup := none
	s.hedgeTok += 0.08 * float64(len(out))
	if s.hedgeTok > 20000 {
		s.hedgeTok = 20000
	}
	if s.cfg.Hedge && len(sp.frames) > 0 && s.hedgeTok >= float64(len(out)) && s.young(sp) && len(s.lanes) > 1 && s.chooser == nil {
		if l := s.nextLane(); l != lane {
			dup = l
			s.hedgeTok -= float64(len(out))
			s.cc.tokens -= float64(size)
			s.stats.PktsOut++
			s.stats.BytesOut += uint64(len(out))
		}
	}
	return outPkt{out, lane, dup}, true
}

func (s *Session) seal(p []byte) ([]byte, uint64) {
	pn := s.nextPN
	s.nextPN++
	out := s.getOut(hdrLen + len(p) + tagLen)
	binary.BigEndian.PutUint64(out, s.sid)
	binary.BigEndian.PutUint64(out[8:], pn)
	copy(s.txNonce[4:], out[8:16])
	return s.aead.Seal(out, s.txNonce[:], p, out[:8]), pn
}

// probePath asks for a tiny ack-eliciting packet on one path (how the bond finds a dead carrier alive again).
func (s *Session) probePath(path int) {
	s.mu.Lock()
	if !s.closed && len(s.probeQ) < 16 {
		s.probeQ = append(s.probeQ, path)
	}
	s.mu.Unlock()
	s.kick()
}

// buildProbe sends one PING on the oldest requested path. It is not paced (a handful of bytes) but is tracked, so
// its ack revives the path and its loss is just counted.
func (s *Session) buildProbe(now time.Time) outPkt {
	lane := s.probeQ[0]
	s.probeQ = s.probeQ[1:]
	out, pn := s.seal([]byte{frPing})
	size := len(out) + ipIcmpHdr
	s.sent = append(s.sent, &sentPkt{pn: pn, at: now, size: size, ctrl: [][]byte{pingFrame}, lane: lane})
	s.inflight += size
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	return outPkt{out, lane, -1}
}

// pathPTO: a tail packet on a slow path is not lost just because the fast path's timeout passed.
func (s *Session) pathPTO(lane int, pto time.Duration) time.Duration {
	if lane < 0 || lane >= len(s.pcc) {
		return pto
	}
	pc := &s.pcc[lane]
	if x := 3 * pc.srtt; x > pto {
		pto = x
	}
	if pc.srtt == 0 && pto < unsampledRTT {
		pto = unsampledRTT
	}
	if pc.reliable && pto < reliablePTO {
		pto = reliablePTO
	}
	return pto
}

// pathLost is the multipath loss rule: a packet is lost when later packets OF ITS OWN PATH were acked (count),
// or when it is older than that path's own loss time.
func (s *Session) pathLost(sp *sentPkt, delay, lt time.Duration, now time.Time) bool {
	if sp.lane < 0 || sp.lane >= len(s.pcc) {
		return now.Sub(sp.at) > lt+delay
	}
	pc := &s.pcc[sp.lane]
	if !pc.have || sp.pn > pc.largest {
		// Nothing later on ITS OWN path has been acked, so there is no evidence about this packet: the ack that
		// triggered this check came over another path, which may simply be faster. Leave it to the path's PTO.
		return false
	}
	if !pc.reliable && pc.largest-sp.pn >= 4 {
		return true
	}
	if pc.srtt == 0 && lt < unsampledRTT {
		lt = unsampledRTT
	}
	if pc.srtt > 0 {
		x := pc.srtt + pc.srtt/4 + 3*time.Millisecond
		if pc.reliable && x < reliableLossTime {
			x = reliableLossTime
		}
		if x > lt {
			lt = x
		}
	}
	return now.Sub(sp.at) > lt+delay
}

func (s *Session) pathSample(lane int, r time.Duration, now time.Time) {
	if lane < 0 || lane >= len(s.pcc) || r <= 0 {
		return
	}
	pc := &s.pcc[lane]
	if pc.srtt == 0 {
		pc.srtt = r
	} else {
		pc.srtt = (7*pc.srtt + r) / 8
	}
	if pc.minRTT == 0 || r < pc.minRTT || now.Sub(pc.minAt) > 10*time.Second {
		pc.minRTT, pc.minAt = r, now
	}
	pc.at = now
}

// unsampledRTT is assumed for a path that has not answered yet: far above any sane carrier, so its first packets
// are not declared lost (and the path killed) before the first ack can possibly arrive.
const unsampledRTT = time.Second

// pathAcked updates the per-path state from a batch of newly acked packets (ascending pn) and returns the rtt
// sample for the pacer, normalised so that it measures queueing, not which path the packet happened to take.
func (s *Session) pathAcked(acked []*sentPkt, largest uint64, delay time.Duration, now time.Time, rtt time.Duration) time.Duration {
	for i := range s.smpBuf {
		s.smpBuf[i] = nil
	}
	for _, sp := range acked {
		if sp.lane < 0 || sp.lane >= len(s.pcc) {
			continue
		}
		if pc := &s.pcc[sp.lane]; !pc.have || sp.pn > pc.largest {
			pc.largest, pc.have = sp.pn, true
		}
		s.smpBuf[sp.lane] = sp
	}
	var norm time.Duration
	for _, sp := range acked {
		var r time.Duration
		if sp.lane >= 0 && sp.lane < len(s.pcc) && s.smpBuf[sp.lane] == sp {
			if r = now.Sub(sp.at); sp.pn == largest {
				r -= delay
			}
			if r > 0 {
				s.pathSample(sp.lane, r, now)
			} else {
				r = 0
			}
		}
		if s.fb != nil {
			s.fb.OnAck(sp.lane, r, sp.size)
		}
	}
	if rtt > 0 {
		var floor, ref time.Duration
		for _, sp := range acked {
			if sp.pn == largest && sp.lane >= 0 && sp.lane < len(s.pcc) {
				floor = s.pcc[sp.lane].minRTT
			}
		}
		for i := range s.pcc {
			if m := s.pcc[i].minRTT; m > 0 && (ref == 0 || m < ref) {
				ref = m
			}
		}
		if floor > 0 && ref > 0 {
			norm = max(rtt-floor+ref, time.Microsecond)
		} else {
			norm = rtt
		}
	}
	var hi time.Duration
	for i := range s.pcc {
		if pc := &s.pcc[i]; pc.srtt > hi && now.Sub(pc.at) < 5*time.Second {
			hi = pc.srtt
		}
	}
	s.cc.pathRTT = hi
	return norm
}

// timers: loss on tail packets, keepalive, pacing adjustments, tombstone pruning.
func (s *Session) timers(now time.Time) {
	s.cc.tick(now)
	if s.sentHead < len(s.sent) {
		pto := s.cc.pto()
		for i := s.sentHead; i < len(s.sent); i++ {
			sp := s.sent[i]
			if sp.done {
				continue
			}
			age := now.Sub(sp.at)
			if age < pto {
				break
			}
			if s.chooser != nil && age < s.pathPTO(sp.lane, pto) {
				continue
			}
			s.lose(sp)
		}
		s.compact()
	}
	if now.Sub(s.lastSend) > 2*time.Second {
		s.wantPing = true
	}
	if !s.lastRecv.IsZero() && now.Sub(s.lastRecv) > 30*time.Second {
		s.resetAll(ErrSessionDead)
		s.lastRecv = time.Time{}
	}
	if len(s.tomb) > 0 && now.Second()%5 == 0 && now.Nanosecond() < 2e6 {
		for id, t := range s.tomb {
			if now.Sub(t) > 2*time.Minute {
				delete(s.tomb, id)
			}
		}
	}
	for l, t := range s.laneSeen {
		if now.Sub(t) > 20*time.Second {
			delete(s.laneSeen, l)
			s.rebuildLanes()
		}
	}
}

func (s *Session) rebuildLanes() {
	if !s.cfg.Server {
		return
	}
	s.lanes = s.lanes[:0]
	for l := range s.laneSeen {
		s.lanes = append(s.lanes, l)
	}
}

func (s *Session) resetAll(err error) {
	for _, st := range s.streams {
		s.killStream(st, err)
	}
	s.prio, s.ctrl = streamQ{}, nil
	s.bulk.reset()
	s.sent, s.sentHead, s.inflight = nil, 0, 0
}

func (s *Session) lose(sp *sentPkt) {
	sp.done, sp.lost = true, true
	s.cc.lostN++
	s.inflight -= sp.size
	if s.fb != nil {
		s.fb.OnLoss(sp.lane)
	}
	if s.fec != nil && len(sp.frames) > 0 {
		s.fec.onLoss()
	}
	if len(sp.frames) > 0 || len(sp.ctrl) > 0 { // a lost datagram-only packet repairs nothing: it only frees its bytes
		s.stats.Retrans++
	}
	for _, f := range sp.frames {
		if st := s.streams[f.sid]; st != nil {
			st.onLost(f)
		}
	}
	s.ctrl = append(s.ctrl, sp.ctrl...)
	// a lost PING needs no resend: the next keepalive tick covers it
	if len(s.ctrl) > 0 {
		keep := s.ctrl[:0]
		for _, c := range s.ctrl {
			if len(c) == 1 && c[0] == frPing {
				continue
			}
			keep = append(keep, c)
		}
		s.ctrl = keep
	}
}

func (s *Session) compact() {
	for s.sentHead < len(s.sent) && s.sent[s.sentHead].done {
		s.freeSent(s.sent[s.sentHead])
		s.sent[s.sentHead] = nil
		s.sentHead++
	}
	if s.sentHead > 2048 {
		s.sent = append(s.sent[:0], s.sent[s.sentHead:]...)
		s.sentHead = 0
	}
}

// ---- receiving ----

func (s *Session) recvLoop() {
	var bo recvBackoff
	for {
		raw, lane, src, err := s.io.Recv()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				bo.fail(err, s.cfg.Logf, "session receive")
				continue
			}
		}
		bo.ok()
		s.handle(raw, lane, src)
	}
}

func (s *Session) handle(raw []byte, lane int, src net.Addr) {
	if len(raw) < hdrLen+tagLen+1 {
		return
	}
	if binary.BigEndian.Uint64(raw) != s.sid {
		return
	}
	pn := binary.BigEndian.Uint64(raw[8:])
	if (pn&dirServerBit != 0) == s.cfg.Server { // our own direction: reflected or foreign
		return
	}
	s.mu.Lock()
	dup := s.rxDup(pn)
	s.mu.Unlock()
	if dup {
		return
	}
	copy(s.rxNonce[4:], raw[8:16])
	plain, err := s.aead.Open(s.openBuf[:0], s.rxNonce[:], raw[hdrLen:], raw[:8])
	if err != nil {
		return // not ours: stay silent
	}
	s.openBuf = plain[:0]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	if s.rxDup(pn) { // re-check under the lock
		return
	}
	if !s.rxAny || pn > s.rxLargest {
		s.rxLargest, s.rxAny, s.rxAt = pn, true, now
	}
	s.rxRing[pn%s.replayWin] = pn + 1
	s.rxRanges.add(pn, pn+1)
	s.rxRanges.trim(s.rxKeep)
	if s.fec != nil {
		s.fecKeep(pn, plain)
	}
	s.lastRecv, s.lastAuth = now, now
	s.stats.PktsIn++
	s.stats.BytesIn += uint64(len(raw))
	if s.cfg.Server {
		s.io.SetPeer(src)
		if _, ok := s.laneSeen[lane]; !ok {
			s.laneSeen[lane] = now
			s.rebuildLanes()
		}
		s.laneSeen[lane] = now
	}
	eliciting := s.parse(plain, now)
	if eliciting {
		if s.ackPend == 0 {
			s.ackSince = now
		}
		s.ackPend++
		s.kick()
	}
}

func (s *Session) rxDup(pn uint64) bool {
	if !s.rxAny || pn > s.rxLargest {
		return false
	}
	if s.rxLargest-pn >= s.replayWin {
		return true
	}
	return s.rxRing[pn%s.replayWin] == pn+1
}

func (s *Session) parse(b []byte, now time.Time) (eliciting bool) {
	r := &reader{b: b}
	for len(r.b) > 0 && r.err == nil {
		switch t := r.byte(); t {
		case frStream, frStreamFin:
			sid, off, n := r.uv(), r.uv(), r.uv()
			data := r.take(n)
			if r.err != nil {
				return
			}
			eliciting = true
			s.onStream(sid, off, data, t == frStreamFin)
		case frAck:
			largest, delayUs, rs := parseAckInto(r, s.ackRs)
			if r.err != nil {
				return
			}
			if s.fec == nil || !s.fec.inRec { // a rebuilt packet's ack is stale: it would skew the RTT sample
				s.onAck(largest, time.Duration(delayUs)*time.Microsecond, rangeSet(rs), now)
			}
			s.ackRs = rs[:0]
		case frWindow:
			sid, max := r.uv(), r.uv()
			if r.err != nil {
				return
			}
			eliciting = true
			if st := s.streams[sid]; st != nil && max > st.peerMax {
				st.peerMax = max
				s.activate(st)
			}
		case frRst:
			sid := r.uv()
			if r.err != nil {
				return
			}
			eliciting = true
			if st := s.streams[sid]; st != nil {
				s.killStream(st, ErrReset)
			} else {
				s.tomb[sid] = now
			}
		case frBoot:
			boot := r.uv()
			if r.err != nil {
				return
			}
			if s.peerBoot != 0 && boot != s.peerBoot { // the server restarted: our streams exist only on our side now
				s.cfg.Logf("server restarted, resetting %d streams", len(s.streams))
				s.resetAll(ErrReset)
			}
			s.peerBoot = boot
		case frPing:
			eliciting = true
		case frDgram:
			flow, port, n := r.uv(), r.uv(), r.uv()
			data := r.take(n)
			if r.err != nil || port > 65535 {
				return
			}
			eliciting = true // acked, so the sender's pacing/inflight accounting releases the packet
			s.onDgram(flow, int(port), data)
		case frFec:
			if s.onFec(r, now) {
				eliciting = true
			}
		default:
			return
		}
	}
	return
}

func (s *Session) onStream(sid, off uint64, data []byte, fin bool) {
	st := s.streams[sid]
	if st == nil {
		if !s.cfg.Server || len(s.streams) >= maxStreams {
			return
		}
		if _, gone := s.tomb[sid]; gone {
			return
		}
		st = s.newStream(sid)
		s.acceptQ = append(s.acceptQ, st)
		s.acceptC.Signal()
	}
	if off+uint64(len(data)) > st.consumed+streamWindow+s.winSlack { // slack for the largest datagram any peer may send
		return // beyond the advertised window
	}
	if fin {
		st.peerFin, st.peerFinO = true, off+uint64(len(data))
	}
	st.insert(off, data)
}

func (s *Session) onAck(largest uint64, delay time.Duration, rs rangeSet, now time.Time) {
	var newly int
	var rtt time.Duration
	acked := s.ackBuf[:0]
	for i := s.sentHead; i < len(s.sent); i++ {
		sp := s.sent[i]
		if sp.done && sp.lost && s.chooser != nil && rs.contains(sp.pn) {
			sp.lost = false // declared lost too early (a slow path): the ack still tells the path is alive and how slow
			s.pathSample(sp.lane, now.Sub(sp.at), now)
			if s.fb != nil {
				s.fb.OnAck(sp.lane, now.Sub(sp.at), 0)
			}
			continue
		}
		if sp.done || !rs.contains(sp.pn) {
			continue
		}
		sp.done = true
		if s.fec != nil && len(sp.frames) > 0 {
			s.fec.onAck()
		}
		if s.chooser != nil {
			acked = append(acked, sp)
		}
		s.inflight -= sp.size
		newly += sp.size
		for _, f := range sp.frames {
			if st := s.streams[f.sid]; st != nil {
				st.onAcked(f)
			}
		}
		if sp.pn == largest {
			rtt = now.Sub(sp.at) - delay
		}
	}
	if s.chooser != nil {
		rtt = s.pathAcked(acked, largest, delay, now, rtt)
		for i := range acked {
			acked[i] = nil
		}
		s.ackBuf = acked[:0]
	}
	if rtt > 0 {
		s.cc.sample(rtt, now)
	}
	// loss: a packet three or more behind the largest acked, or older than one RTT plus a quarter
	lt := s.cc.lossTime()
	for i := s.sentHead; i < len(s.sent); i++ {
		sp := s.sent[i]
		if sp.pn >= largest {
			break
		}
		if sp.done {
			continue
		}
		if s.chooser != nil {
			if s.pathLost(sp, delay, lt, now) {
				s.lose(sp)
			}
			continue
		}
		if (largest-sp.pn >= 4 && !s.cc.reliable) || now.Sub(sp.at) > lt+delay {
			s.lose(sp)
		}
	}
	s.compact()
}

// Alive reports whether authenticated packets arrived from the peer in the last 10 seconds.
// CarrierStats is the per-carrier view of a bonded session (nil for a single-carrier one).
func (s *Session) CarrierStats() []CarrierStat {
	if ps, ok := s.io.(PathStatser); ok {
		return ps.PathStats()
	}
	return nil
}

// Alive reports whether an authenticated packet from the peer arrived in the last 10 s. The peer pings at least
// every 2 s, so an idle but working link stays alive.
func (s *Session) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastRecv.IsZero() && time.Since(s.lastRecv) < 10*time.Second
}

// LastRecv is when the last authenticated packet from the peer arrived (zero: none yet). Unlike Alive's clock it is
// never reset, so a monitor can see how long the link has been silent.
func (s *Session) LastRecv() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuth
}

// young: the packet is small, or carries only the first bytes of its streams (handshakes, requests, replies):
// those are the ones a single random loss would hurt most, so they are sent twice on different lanes.
func (s *Session) young(sp *sentPkt) bool {
	n := 0
	for _, f := range sp.frames {
		n += f.n
		st := s.streams[f.sid]
		if st == nil || f.off > 32<<10 {
			return false
		}
	}
	return n <= 330 || len(sp.frames) > 0
}
