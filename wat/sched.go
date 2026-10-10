package wat

// streamQ is a FIFO of streams that does not allocate per push (a plain `q = q[1:]` queue re-grows its array
// every time the slice runs off the end: measured as the third biggest allocator in BenchmarkSessionBulk).
type streamQ struct {
	a    []*Stream
	head int
}

func (q *streamQ) len() int { return len(q.a) - q.head }

func (q *streamQ) push(st *Stream) {
	if q.head > 64 && q.head*2 >= len(q.a) { // reclaim the consumed front in place
		n := copy(q.a, q.a[q.head:])
		clear(q.a[n:])
		q.a, q.head = q.a[:n], 0
	}
	q.a = append(q.a, st)
}

func (q *streamQ) pop() *Stream {
	if q.head == len(q.a) {
		return nil
	}
	st := q.a[q.head]
	q.a[q.head] = nil
	q.head++
	if q.head == len(q.a) {
		q.a, q.head = q.a[:0], 0
	}
	return st
}

// any reports whether f is true for some queued stream.
func (q *streamQ) any(f func(*Stream) bool) bool {
	for _, st := range q.a[q.head:] {
		if f(st) {
			return true
		}
	}
	return false
}

// fairQ schedules bulk streams. Streams are grouped (Stream.SetGroup: the public port they belong to); the group
// that has been sent the fewest bytes goes next, and inside a group streams take turns. One port's eight heavy
// downloads therefore get the same share as another port's single one. With every stream in group 0 (the default)
// this is the plain FIFO round-robin it replaced.
type fairQ struct {
	groups []*fairGroup
	n      int // queued streams
	last   *fairGroup
}

type fairGroup struct {
	id     uint32
	q      streamQ
	served uint64 // bytes charged to the group
}

func (f *fairQ) group(id uint32) *fairGroup {
	for _, g := range f.groups {
		if g.id == id {
			return g
		}
	}
	g := &fairGroup{id: id}
	f.groups = append(f.groups, g)
	return g
}

func (f *fairQ) push(st *Stream) {
	g := st.fg
	if g == nil || g.id != st.group {
		g = f.group(st.group)
		st.fg = g
	}
	if g.q.len() == 0 && g != f.last { // waking from idle: no credit for the time it did not ask for anything
		var lo uint64
		found := false
		for _, o := range f.groups {
			if o != g && o.q.len() > 0 && (!found || o.served < lo) {
				lo, found = o.served, true
			}
		}
		if found && g.served < lo {
			g.served = lo
		}
	}
	g.q.push(st)
	f.n++
}

func (f *fairQ) pop() *Stream {
	var best *fairGroup
	for _, g := range f.groups {
		if g.q.len() > 0 && (best == nil || g.served < best.served) {
			best = g
		}
	}
	if best == nil {
		return nil
	}
	f.last = best
	f.n--
	return best.q.pop()
}

func (f *fairQ) charge(st *Stream, n int) {
	if st.fg != nil && n > 0 {
		st.fg.served += uint64(n)
	}
}

func (f *fairQ) any(fn func(*Stream) bool) bool {
	for _, g := range f.groups {
		if g.q.any(fn) {
			return true
		}
	}
	return false
}

func (f *fairQ) reset() {
	for _, g := range f.groups {
		g.q = streamQ{}
	}
	f.n = 0
}

// ---- buffer ownership
//
// A sealed datagram is handed to PacketIO.Send. The session may reuse its buffer only when the carrier says it is
// done with the slice when Send returns (Copier): the raw-socket and UDP carriers copy into the kernel, but the tcp
// pool, tls, ws/h2/grpc and bond carriers queue the slice and keep using it afterwards, so those get a fresh one.

// Copier is the optional interface of a PacketIO / RawIO that never retains the slice passed to Send / SendTo.
type Copier interface{ CopiesOnSend() bool }

func copies(x any) bool {
	c, ok := x.(Copier)
	return ok && c.CopiesOnSend()
}

var pingFrame = []byte{frPing} // shared: control frames are never modified

func (s *Session) getOut(n int) []byte {
	select {
	case b := <-s.outFree: // nil channel (carrier retains buffers): never ready
		if cap(b) >= n {
			return b[:hdrLen]
		}
	default:
	}
	return make([]byte, hdrLen, max(n, s.maxPlain+overhead))
}

func (s *Session) putOut(b []byte) {
	if s.outFree != nil {
		select {
		case s.outFree <- b:
		default:
		}
	}
}

// newSent / freeSent recycle sentPkt records (and their frame slices) once compact() has passed them.
func (s *Session) newSent() *sentPkt {
	if n := len(s.spFree); n > 0 {
		sp := s.spFree[n-1]
		s.spFree = s.spFree[:n-1]
		return sp
	}
	return &sentPkt{}
}

func (s *Session) freeSent(sp *sentPkt) {
	if len(s.spFree) >= 4096 {
		return
	}
	clear(sp.ctrl)
	*sp = sentPkt{frames: sp.frames[:0], ctrl: sp.ctrl[:0]}
	s.spFree = append(s.spFree, sp)
}

func isChooser(x any) bool {
	ch, ok := x.(PathChooser)
	return ok && ch.NumPaths() > 0
}
