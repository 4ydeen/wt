package wat

import "time"

// Adaptive FEC (Config.FEC, off by default): one XOR parity packet after a burst of small packets, so a single lost
// packet of the group is rebuilt by the receiver instead of waiting for a PTO (~1.25 RTT+) or for four later acks.
//
// Wire: frFec = n, base pn, n x (pn-base, plaintext length), then the parity bytes (to the end of the frame). The
// frame sits ALONE in its packet: an old peer stops at the unknown type and loses nothing else, and the packet is not
// ack-eliciting. Both ends must run FEC (>= 1.7.0) for it to help: a peer with FEC off parses and ignores the frame.
// Only packets whose plaintext is at most maxPlain-fecHdrMax are covered, so a parity packet always fits one
// datagram; in bulk the packets are full and nothing is covered (no overhead).
const (
	fecMaxK   = 16
	fecMinK   = 4
	fecRing   = 64 // received plaintexts kept for reconstruction
	fecHdrMax = 80 // frame header worst case: type, n, 10 B base, 16 x (2 + 2), length slack
)

type fecEnt struct {
	pn  uint64 // tx: packet number; rx: pn+1 (0 = empty)
	buf []byte
}

type fecState struct {
	tx    [fecMaxK]fecEnt // sent, not yet covered by a parity packet (oldest first)
	txN   int
	rx    [fecRing]fecEnt
	loss  float64 // EWMA of the packet loss rate seen by the sender
	inRec bool
	out   []byte
}

func newFec() *fecState { return &fecState{loss: 0.02} }

// k adapts to the loss rate: the more loss, the smaller the group (a second loss inside a group is unrepairable).
func (f *fecState) k() int {
	k := fecMaxK
	if f.loss > 0 {
		k = int(0.2 / f.loss)
	}
	return min(max(k, fecMinK), fecMaxK)
}

func (f *fecState) onAck()  { f.loss -= f.loss / 256 }
func (f *fecState) onLoss() { f.loss += (1 - f.loss) / 256 }

// fecNoteSent remembers the plaintext of a data-bearing packet for the next parity.
func (s *Session) fecNoteSent(pn uint64, p []byte) {
	f := s.fec
	if len(p) > s.maxPlain-fecHdrMax {
		return
	}
	if f.txN == fecMaxK { // keep the newest fecMaxK
		e := f.tx[0]
		copy(f.tx[:], f.tx[1:])
		f.tx[fecMaxK-1] = e
		f.txN--
	}
	e := &f.tx[f.txN]
	e.pn, e.buf = pn, append(e.buf[:0], p...)
	f.txN++
}

// fecDue builds the parity packet when a burst ended (nothing left to send) or k small packets went out while the
// session is not cwnd-limited.
func (s *Session) fecDue(now time.Time) (outPkt, bool) {
	f := s.fec
	if f.txN == 0 || s.cc.tokens <= 0 {
		return outPkt{}, false
	}
	k := f.k()
	if s.hasWork() && (f.txN < k || s.cc.limited) {
		return outPkt{}, false
	}
	grp := f.tx[:f.txN]
	if len(grp) > k {
		grp = grp[len(grp)-k:]
	}
	lane := -1
	if s.chooser == nil {
		if lane = s.nextLane(); lane < 0 {
			return outPkt{}, false
		}
	}
	L := 0
	for _, e := range grp {
		L = max(L, len(e.buf))
	}
	base := grp[0].pn
	p := append(f.out[:0], frFec)
	p = appendUv(p, uint64(len(grp)))
	p = appendUv(p, base)
	for _, e := range grp {
		p = appendUv(p, e.pn-base)
		p = appendUv(p, uint64(len(e.buf)))
	}
	at := len(p)
	for i := 0; i < L; i++ {
		p = append(p, 0)
	}
	for _, e := range grp {
		xorInto(p[at:], e.buf)
	}
	f.out = p[:0]
	f.txN = 0
	if s.chooser != nil {
		lane = s.chooser.ChoosePath(len(p)+overhead, true)
	}
	out, _ := s.seal(p)
	s.cc.tokens -= float64(len(out) + ipIcmpHdr) // paced, but not tracked: it is never acked and never retransmitted
	s.lastSend = now
	s.stats.PktsOut++
	s.stats.BytesOut += uint64(len(out))
	s.stats.FecSent++
	return outPkt{out, lane, -1}, true
}

func xorInto(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

// fecKeep stores the plaintext of a received packet (under s.mu).
func (s *Session) fecKeep(pn uint64, plain []byte) {
	if len(plain) > s.maxPlain-fecHdrMax {
		return
	}
	e := &s.fec.rx[pn%fecRing]
	e.pn, e.buf = pn+1, append(e.buf[:0], plain...)
}

// onFec handles a parity frame (r is positioned after the type byte). It returns whether the rebuilt packet was
// ack-eliciting.
func (s *Session) onFec(r *reader, now time.Time) bool {
	n := r.uv()
	base := r.uv()
	if r.err != nil || n == 0 || n > fecMaxK {
		r.err = errBadFrame
		return false
	}
	var pns [fecMaxK]uint64
	var lens [fecMaxK]int
	for i := 0; i < int(n); i++ {
		pns[i] = base + r.uv()
		lens[i] = int(r.uv())
	}
	parity := r.take(uint64(len(r.b)))
	f := s.fec
	if r.err != nil || f == nil || f.inRec {
		return false
	}
	miss := -1
	for i := 0; i < int(n); i++ {
		if lens[i] > len(parity) {
			return false
		}
		if s.rxAny && s.rxDup(pns[i]) {
			continue
		}
		if miss >= 0 {
			return false // two missing: one parity cannot repair them
		}
		miss = i
	}
	if miss < 0 {
		return false
	}
	rec := append([]byte(nil), parity...)
	for i := 0; i < int(n); i++ {
		if i == miss {
			continue
		}
		e := &f.rx[pns[i]%fecRing]
		if e.pn != pns[i]+1 || len(e.buf) != lens[i] {
			return false
		}
		xorInto(rec, e.buf)
	}
	rec = rec[:lens[miss]]
	pn := pns[miss]
	if !s.rxAny || pn > s.rxLargest {
		s.rxLargest, s.rxAny, s.rxAt = pn, true, now
	}
	s.rxRing[pn%s.replayWin] = pn + 1
	s.rxRanges.add(pn, pn+1)
	s.rxRanges.trim(s.rxKeep)
	s.fecKeep(pn, rec)
	s.stats.FecRecovered++
	f.inRec = true
	el := s.parse(rec, now)
	f.inRec = false
	return el
}
