package wat

import (
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

var (
	ErrReset        = errors.New("wat: stream reset")
	ErrClosed       = errors.New("wat: closed")
	ErrTooManyConns = errors.New("wat: too many streams")
)

type frameRef struct {
	sid, off uint64
	n        int
	fin      bool
}

type seg struct {
	off  uint64
	data []byte
}

// Stream is one reliable, ordered byte stream (one TCP connection) inside a Session.
type Stream struct {
	s  *Session
	id uint64

	rc, wc *sync.Cond // readers / writers wait on these (both guarded by s.mu)

	// send side
	sbuf      []byte // unacknowledged data; sbuf[0] is stream offset sbase
	sbase     uint64
	snext     uint64 // next never-sent offset
	retx      []frameRef
	acked     rangeSet
	peerMax   uint64
	finQueued bool
	finSent   bool
	finAcked  bool
	finOff    uint64
	sentTotal uint64
	inActive  bool
	group     uint32 // fair-queue group (SetGroup): the public port the stream belongs to
	fg        *fairGroup
	sroot     []byte // backing array of sbuf (sbuf is a window into it, so acked bytes at the front can be reclaimed)

	// receive side
	rnext    uint64
	segs     []seg
	ready    []byte
	rroot    []byte    // backing array of ready, same idea
	slowWin  uint64    // >0: the smaller window advertised while the local reader lags (tuneSlow)
	shrunkAt time.Time // last time onAcked gave back an oversized send buffer
	slowAt   time.Time
	slowC    uint64
	consumed uint64
	advMax   uint64
	win      uint64 // window this end advertises beyond consumed: streamWindow, auto-tuned upward (see tuneWindow)
	tuneAt   time.Time
	tuneRx   uint64 // rnext at the start of the current measuring epoch
	peerFin  bool
	peerFinO uint64
	eof      bool

	err  error
	dead bool
}

func (s *Session) newStream(id uint64) *Stream {
	st := &Stream{s: s, id: id, peerMax: streamWindow, advMax: streamWindow, win: streamWindow}
	st.rc = sync.NewCond(&s.mu)
	st.wc = sync.NewCond(&s.mu)
	s.streams[id] = st
	return st
}

func (st *Stream) sendable() bool {
	if len(st.retx) > 0 {
		return true
	}
	if st.snext < st.sbase+uint64(len(st.sbuf)) && st.snext < st.peerMax {
		return true
	}
	return st.finQueued && !st.finSent && st.snext == st.finOff
}

// Write queues data for sending; it blocks while the unacknowledged buffer is full.
func (st *Stream) Write(b []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for len(b) > 0 {
		for st.err == nil && !st.finQueued && len(st.sbuf) >= st.writeCap() {
			st.wc.Wait()
		}
		if st.err != nil {
			return total, st.err
		}
		if st.finQueued {
			return total, ErrClosed
		}
		n := st.writeCap() - len(st.sbuf)
		if n > len(b) {
			n = len(b)
		}
		st.makeRoom(n)
		st.sbuf = append(st.sbuf, b[:n]...)
		b = b[n:]
		total += n
		s.activate(st)
	}
	return total, nil
}

// sendCap is how many unacknowledged bytes Write may buffer: 4 MB, or what the peer has advertised beyond that
// (a peer that never advertises more than the implicit 4 MB window keeps exactly the old behaviour).
func (st *Stream) sendCap() int {
	if st.peerMax > st.sbase+sendBufMax {
		return int(min(st.peerMax-st.sbase, maxStreamWin))
	}
	return sendBufMax
}

// writeCap is sendCap, but at most sendStage beyond what the peer's window lets us send: while a slow reader keeps
// the peer's window shut, there is no point holding another 4 MB here (2.4.3; the local source refills fast).
func (st *Stream) writeCap() int {
	room := 0
	if st.peerMax > st.sbase {
		room = int(min(st.peerMax-st.sbase, maxStreamWin))
	}
	return min(st.sendCap(), room+sendStage)
}

// tuneSlow shrinks the window this end advertises while the local reader, not the tunnel, sets the pace. A user on a
// slow last mile otherwise parks a full window (4 MB) here and as much again at the sender (field 2026-10-12: 180
// streams held ~700 MB on each end). Once per RTT: if unread data keeps piling up, the window becomes slowWinRTTs
// RTTs of what the reader actually consumed (at least slowWinMin); when the backlog runs dry it grows back by half. The
// advertised limit never moves back, updates just pause, so an older sender is unaffected (2.4.3).
func (st *Stream) tuneSlow(now time.Time) {
	if st.slowAt.IsZero() {
		st.slowAt, st.slowC = now, st.consumed
		return
	}
	rtt := max(st.s.cc.srtt, 5*time.Millisecond)
	el := now.Sub(st.slowAt)
	if el < rtt {
		return
	}
	used := st.consumed - st.slowC
	st.slowAt, st.slowC = now, st.consumed
	lim := st.win
	if st.slowWin > 0 {
		lim = st.slowWin
	}
	if st.rnext-st.consumed > lim/2 {
		w := max(uint64(float64(used)*float64(rtt)/float64(el))*slowWinRTTs, slowWinMin)
		st.slowWin = w
		if w >= st.win {
			st.slowWin = 0
		}
	} else if st.slowWin > 0 && st.rnext-st.consumed < lim/4 { // the reader is starving: open up again
		st.slowWin += st.slowWin / 2
		if st.slowWin >= st.win {
			st.slowWin = 0
		}
	}
}

// tuneWindow grows the window this end advertises (receiver-driven; the sender just honours frWindow). Once per
// RTT it looks at how much arrived: a sender that fills most of the window every RTT is window-limited, so the
// window doubles toward 2x the observed bytes per RTT (cap maxStreamWin per stream, maxSessionWin extra per session).
// A reader that lags (more than a quarter of the window unread) stops the growth. The advertised limit never moves
// back, so nothing already granted is refused.
func (st *Stream) tuneWindow() {
	s := st.s
	if s.noWinTune {
		return
	}
	now := time.Now()
	if st.tuneAt.IsZero() {
		st.tuneAt, st.tuneRx = now, st.rnext
		return
	}
	rtt := s.cc.srtt
	if rtt < 5*time.Millisecond {
		rtt = 5 * time.Millisecond
	}
	if now.Sub(st.tuneAt) < rtt {
		return
	}
	got := st.rnext - st.tuneRx
	st.tuneAt, st.tuneRx = now, st.rnext
	if st.win >= maxStreamWin || got < st.win/2 || st.rnext-st.consumed > st.win/4 {
		return
	}
	nw := min(2*got, 2*st.win, maxStreamWin)
	if nw <= st.win || s.winExtra+(nw-st.win) > maxSessionWin {
		return
	}
	s.winExtra += nw - st.win
	st.win = nw
}

// CloseWrite sends FIN: the peer's Read returns io.EOF after the buffered data.
func (st *Stream) CloseWrite() error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.err != nil {
		return st.err
	}
	if !st.finQueued {
		st.finQueued = true
		st.finOff = st.sbase + uint64(len(st.sbuf))
		s.activate(st)
	}
	return nil
}

// Read returns in-order bytes, io.EOF after the peer's FIN.
func (st *Stream) Read(b []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(st.ready) == 0 && !st.eof && st.err == nil {
		st.rc.Wait()
	}
	if len(st.ready) == 0 {
		if st.err != nil {
			return 0, st.err
		}
		st.maybeFinish()
		return 0, io.EOF
	}
	n := copy(b, st.ready)
	st.ready = st.ready[n:]
	if w := st.slowWin; w > 0 && cap(st.rroot) > 1<<20 && uint64(cap(st.rroot)) > 2*w && uint64(len(st.ready)) <= w {
		nb := make([]byte, len(st.ready), 2*w) // lagging reader (tuneSlow): give back the big buffer
		copy(nb, st.ready)
		st.rroot, st.ready = nb[:0], nb
	}
	if len(st.ready) == 0 {
		if cap(st.rroot) > keepBuf { // keep a working buffer (re-growing it from zero after every drain cost ~10 % CPU at 100 MB/s)
			st.rroot = nil
		}
		st.ready = nil
	}
	st.consumed += uint64(n)
	st.tuneWindow()
	st.tuneSlow(time.Now())
	lim := st.win
	if st.slowWin > 0 {
		lim = st.slowWin
	}
	if st.consumed+lim > st.advMax && st.consumed+lim-st.advMax >= lim/4 {
		st.advMax = st.consumed + lim
		var f []byte
		f = append(f, frWindow)
		f = appendUv(f, st.id)
		f = appendUv(f, st.advMax)
		s.ctrl = append(s.ctrl, f)
		s.kick()
	}
	st.maybeFinish()
	return n, nil
}

// Reset aborts the stream in both directions.
func (st *Stream) Reset() {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.dead {
		return
	}
	var f []byte
	f = append(f, frRst)
	f = appendUv(f, st.id)
	s.ctrl = append(s.ctrl, f)
	s.kick()
	s.killStream(st, ErrReset)
}

func (s *Session) killStream(st *Stream, err error) {
	if st.dead {
		return
	}
	st.dead = true
	s.winExtra -= st.win - streamWindow
	if st.err == nil {
		st.err = err
	}
	delete(s.streams, st.id)
	s.tomb[st.id] = s.now
	s.winExtra -= st.win - streamWindow
	st.rc.Broadcast()
	st.wc.Broadcast()
}

// maybeFinish retires a stream once both directions are complete and drained.
func (st *Stream) maybeFinish() {
	if st.dead || !st.finAcked || st.sbase != st.finOff || !st.eof || len(st.ready) > 0 {
		return
	}
	s := st.s
	st.dead = true
	delete(s.streams, st.id)
	s.tomb[st.id] = s.now
	s.winExtra -= st.win - streamWindow
	st.rc.Broadcast()
	st.wc.Broadcast()
}

func (st *Stream) onAcked(f frameRef) {
	if f.n > 0 {
		st.acked.add(f.off, f.off+uint64(f.n))
		if len(st.acked) > 0 && st.acked[0].lo <= st.sbase && st.acked[0].hi > st.sbase {
			drop := st.acked[0].hi - st.sbase
			if drop > uint64(len(st.sbuf)) {
				drop = uint64(len(st.sbuf))
			}
			st.sbuf = st.sbuf[drop:]
			if len(st.sbuf) == 0 {
				if cap(st.sroot) > keepBuf {
					st.sroot, st.sbuf = nil, nil // do not pin a big buffer on an idle stream
				} else {
					st.sbuf = st.sroot[:0]
				}
			} else if c := st.writeCap(); cap(st.sroot) > 1<<20 && cap(st.sroot) > 4*c && len(st.sbuf) <= c &&
				st.s.now.Sub(st.shrunkAt) > time.Second {
				// the peer's window shut (slow reader): give back the big buffer, at most once a second. The cap moves
				// with every ack and window update, so shrinking on each of them re-copied the buffer per ack: 2.4.3
				// allocated 100x the data in onAcked and tripled the sender's CPU (field 2026-10-12).
				st.shrunkAt = st.s.now
				nb := make([]byte, len(st.sbuf), 2*c)
				copy(nb, st.sbuf)
				st.sroot, st.sbuf = nb, nb
			}
			st.sbase += drop
			if st.acked[0].hi <= st.sbase {
				st.acked = append(st.acked[:0], st.acked[1:]...)
			}
			st.wc.Broadcast()
		}
	}
	if f.fin {
		st.finAcked = true
	}
	st.maybeFinish()
}

func (st *Stream) onLost(f frameRef) {
	if f.n > 0 && (st.acked.covered(f.off, f.off+uint64(f.n)) || f.off+uint64(f.n) <= st.sbase) {
		return
	}
	if f.n == 0 && f.fin && st.finAcked {
		return
	}
	st.retx = append(st.retx, f)
	st.s.activate(st)
}

func uvlen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// emit appends at most one frame to p. fit=false means the next frame does not fit the remaining room.
func (st *Stream) emit(p []byte, sp *sentPkt, room int) (np []byte, sent, fit bool) {
	hdr := 1 + uvlen(st.id) + 10 + 2
	for len(st.retx) > 0 {
		f := st.retx[0]
		if f.n > 0 && (st.acked.covered(f.off, f.off+uint64(f.n)) || f.off+uint64(f.n) <= st.sbase) {
			st.retx = st.retx[1:]
			continue
		}
		if f.n == 0 && f.fin && st.finAcked {
			st.retx = st.retx[1:]
			continue
		}
		off, n := f.off, f.n
		if off < st.sbase { // the front part was acked and freed meanwhile
			cut := int(st.sbase - off)
			off, n = st.sbase, n-cut
		}
		if hdr+n > room {
			return p, false, false
		}
		st.retx = st.retx[1:]
		p = st.appendFrame(p, off, n, f.fin)
		sp.frames = append(sp.frames, frameRef{st.id, off, n, f.fin})
		return p, true, true
	}
	end := st.sbase + uint64(len(st.sbuf))
	limit := end
	if st.peerMax < limit {
		limit = st.peerMax
	}
	if st.snext < limit {
		n := int(limit - st.snext)
		if n > room-hdr {
			n = room - hdr
		}
		if n <= 0 {
			return p, false, false
		}
		fin := st.finQueued && st.snext+uint64(n) == st.finOff
		off := st.snext
		p = st.appendFrame(p, off, n, fin)
		sp.frames = append(sp.frames, frameRef{st.id, off, n, fin})
		st.snext += uint64(n)
		st.sentTotal += uint64(n)
		if fin {
			st.finSent = true
		}
		return p, true, true
	}
	if st.finQueued && !st.finSent && st.snext == st.finOff {
		if hdr > room {
			return p, false, false
		}
		p = st.appendFrame(p, st.snext, 0, true)
		sp.frames = append(sp.frames, frameRef{st.id, st.snext, 0, true})
		st.finSent = true
		return p, true, true
	}
	return p, false, true
}

func (st *Stream) appendFrame(p []byte, off uint64, n int, fin bool) []byte {
	t := byte(frStream)
	if fin {
		t = frStreamFin
	}
	p = append(p, t)
	p = appendUv(p, st.id)
	p = appendUv(p, off)
	p = appendUv(p, uint64(n))
	if n > 0 {
		p = append(p, st.sbuf[off-st.sbase:off-st.sbase+uint64(n)]...)
	}
	return p
}

// insert stores received bytes without overlap, then delivers whatever became contiguous.
func (st *Stream) insert(off uint64, data []byte) {
	if off == st.rnext && len(st.segs) == 0 && len(data) > 0 { // in order, nothing buffered: no copy into a segment first
		st.appendReady(data)
		st.rnext += uint64(len(data))
		data = nil
	}
	for len(data) > 0 {
		if off < st.rnext {
			skip := st.rnext - off
			if skip >= uint64(len(data)) {
				break
			}
			data, off = data[skip:], off+skip
			continue
		}
		i := sort.Search(len(st.segs), func(i int) bool { return st.segs[i].off+uint64(len(st.segs[i].data)) > off })
		if i < len(st.segs) && st.segs[i].off <= off {
			skip := st.segs[i].off + uint64(len(st.segs[i].data)) - off
			if skip >= uint64(len(data)) {
				break
			}
			data, off = data[skip:], off+skip
			continue
		}
		limit := uint64(len(data))
		if i < len(st.segs) && st.segs[i].off < off+limit {
			limit = st.segs[i].off - off
		}
		cp := append([]byte(nil), data[:limit]...)
		st.segs = append(st.segs, seg{})
		copy(st.segs[i+1:], st.segs[i:])
		st.segs[i] = seg{off, cp}
		data, off = data[limit:], off+limit
	}
	for len(st.segs) > 0 && st.segs[0].off == st.rnext {
		st.appendReady(st.segs[0].data)
		st.rnext += uint64(len(st.segs[0].data))
		st.segs = st.segs[1:]
	}
	if st.peerFin && st.rnext == st.peerFinO {
		st.eof = true
	}
	st.rc.Broadcast()
	st.maybeFinish()
}

// SetGroup puts the stream into a fair-queue group (the public port it serves). Bulk streams of different groups get
// equal shares of the link; streams in one group share that group's share. The default group is 0.
func (st *Stream) SetGroup(g uint32) {
	s := st.s
	s.mu.Lock()
	st.group = g
	s.mu.Unlock()
}

// makeRoom guarantees room for n more bytes at the end of sbuf without allocating when the acked front of the
// buffer can be reclaimed. (append on a resliced `sbuf[drop:]` loses that front for good and re-allocates the whole
// unacked window every time the capacity runs out: measured 5x the bytes written, BenchmarkSessionBulk.)
func (st *Stream) makeRoom(n int) {
	live := len(st.sbuf)
	if cap(st.sbuf)-live >= n {
		return
	}
	if cap(st.sroot) >= live+n {
		copy(st.sroot[:live], st.sbuf)
		st.sbuf = st.sroot[:live]
		return
	}
	nb := make([]byte, live, max(min(2*(live+n), st.sendCap()), live+n, 4096)) // doubling, but not past the cap
	copy(nb, st.sbuf)
	st.sroot, st.sbuf = nb, nb
}

// appendReady adds in-order bytes for Read. When Read has drained ready, the next bytes start again at the front of
// the same backing array instead of allocating a new one per packet.
//
// When the end of the backing array is reached while Read has consumed its front, the unread bytes move back to the
// front instead of growing a new array (same idea as makeRoom on the send side).
func (st *Stream) appendReady(data []byte) {
	old := st.ready
	if len(old) == 0 {
		old = st.rroot[:0]
	} else if cap(old)-len(old) < len(data) && cap(st.rroot) >= len(old)+len(data) {
		old = st.rroot[:copy(st.rroot[:len(old)], old)]
	}
	st.ready = append(old, data...)
	if cap(old)-len(old) < len(data) { // append moved to a new backing array (it starts at its front)
		st.rroot = st.ready[:0]
	}
}
