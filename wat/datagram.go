package wat

// Unreliable datagrams (UDP forwarding). A datagram rides in a frDgram frame inside an ordinary encrypted packet, so
// it is paced and counted in flight like everything else, but it is never retransmitted, never tracked per frame
// and has no flow control. When the peer is too slow or the queue is full the datagram is dropped, like UDP would.
//
// Compatibility: a peer older than 1.2.0 stops parsing a packet at the unknown frame type (parse's default case) and
// carries on; the session survives. Datagrams are put LAST in a packet so the stream frames before them still land.
// Nothing is sent unless SendDatagram is called, so existing deployments see no wire change; but both ends must be
// upgraded before any udp port is configured, or the old end silently discards every datagram.

const (
	dgramQueueMax   = 512     // datagrams waiting to be sent
	dgramQueueBytes = 1 << 20 // and their total size
	dgramRxCap      = 1024    // received datagrams waiting for the consumer
)

// Datagram is one received unreliable datagram. Data is owned by the receiver.
type Datagram struct {
	Flow uint64
	Port int
	Data []byte
}

// SendDatagram queues p on flow (port is the server-side target; send it on every datagram). It returns false and
// counts a drop when the queue is full, the session is closed, or p cannot fit one packet (no fragmentation).
func (s *Session) SendDatagram(flow uint64, port int, p []byte) bool {
	f := make([]byte, 0, len(p)+24)
	f = append(f, frDgram)
	f = appendUv(f, flow)
	f = appendUv(f, uint64(port))
	f = appendUv(f, uint64(len(p)))
	f = append(f, p...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	if len(f) > s.maxPlain {
		s.stats.DgramDropSize++
		s.mu.Unlock()
		return false
	}
	if len(s.dq) >= dgramQueueMax || s.dqBytes+len(f) > dgramQueueBytes {
		s.stats.DgramDropQueue++
		s.mu.Unlock()
		return false
	}
	s.dq = append(s.dq, f)
	s.dqBytes += len(f)
	s.mu.Unlock()
	s.kick()
	return true
}

// MaxDatagram is the largest payload SendDatagram accepts for the given flow id and port (conservative: 10-byte flow).
func (s *Session) MaxDatagram() int { return s.maxPlain - 1 - 10 - 3 - 3 }

// Datagrams delivers received datagrams. It never closes; select on Done() as well.
func (s *Session) Datagrams() <-chan Datagram { return s.dgIn }

// Done is closed when the session is closed.
func (s *Session) Done() <-chan struct{} { return s.stop }

// takeDgrams appends queued frames to dst while they fit in room. With shared set (streams also want this packet)
// the first datagram may use all of room but further ones only the first half, so streams keep progressing.
func (s *Session) takeDgrams(dst []byte, room int, shared bool) []byte {
	limit := room
	for len(s.dq) > 0 {
		f := s.dq[0]
		if len(dst)+len(f) > limit {
			break
		}
		dst = append(dst, f...)
		s.dq[0] = nil
		s.dq = s.dq[1:]
		s.dqBytes -= len(f)
		s.stats.DgramSent++
		if shared {
			limit = room / 2
		}
	}
	if len(s.dq) == 0 {
		s.dq, s.dqBytes = nil, 0
	}
	return dst
}

// onDgram runs under s.mu: copy and hand over without blocking.
func (s *Session) onDgram(flow uint64, port int, data []byte) {
	d := Datagram{flow, port, append([]byte(nil), data...)}
	select {
	case s.dgIn <- d:
		s.stats.DgramRecv++
	default:
		s.stats.DgramDropRx++
	}
}
