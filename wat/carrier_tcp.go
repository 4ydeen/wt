package wat

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The tcp pool carrier: N TCP connections between one client and the server, each datagram framed as
// uint16 length + bytes. No crypto and no retransmit here: the session authenticates every datagram and repairs
// loss, so every queue is bounded and a full queue DROPS (blocking would stall every stream). A dead connection is
// closed, its queued packets are lost (loss, repaired by the session) and the client redials it with backoff.
// The tls carrier (carrier_tls.go) is this same pool with a different dial func / listener.
//
// Server side a client is identified by a random 8-byte pool id it sends first on every connection, since the
// connections of one pool come from different source ports. The hello is unauthenticated on purpose: the Server only
// admits sids whose packets authenticate, so all a stranger can do here is occupy capped slots for a few seconds.

const (
	poolQueue     = 256      // packets queued per connection
	poolMaxFrame  = 32 << 10 // receive bound; datagrams are at most poolMaxMTU
	poolBufSize   = 64 << 10
	poolHelloWait = 5 * time.Second
	poolMaxPools  = 4096
	poolMaxConns  = 64 // per pool
	poolRxQueue   = 1024
	// DefaultPoolConns is the default connection count of a client pool.
	DefaultPoolConns = 8
)

// poolProfile: TCP carries every datagram, in order per connection, so the session relaxes its loss detection and
// delay judgement (see Profile.Reliable).
var poolDrops atomic.Int64

const poolMaxMTU = 16 << 10

//
// MTU 4096 and an 8 MB/s start are measured defaults (2026-10-09, bench link 40 ms / 0.2 % / 100 Mbit): 640 B datagrams
// cost 4x the CPU per MB and a 1.5 MB/s start spends a quarter of a 32 MB transfer ramping up.
var poolProfile = Profile{Reliable: true, MTU: 4096, MaxMTU: poolMaxMTU, InitBps: 8e6}

// poolAddr identifies a client pool on the server: it is the net.Addr handed to Server and back to SendTo.
type poolAddr struct {
	key string
	ip  string // remote IP of the connection the packet came in on (informational: Server.Clients)
}

func (poolAddr) Network() string  { return "pool" }
func (a poolAddr) String() string { return hex.EncodeToString([]byte(a.key)) }

// poolConn is one framed connection with its own bounded send queue.
type poolConn struct {
	c    net.Conn
	q    chan []byte
	done chan struct{}
	once sync.Once
}

func newPoolConn(c net.Conn) *poolConn {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return &poolConn{c: c, q: make(chan []byte, poolQueue), done: make(chan struct{})}
}

func (pc *poolConn) fail() {
	pc.once.Do(func() {
		close(pc.done)
		pc.c.Close()
	})
}

// enqueue never blocks: false means the queue is full (or the conn is dead) and the packet was dropped.
func (pc *poolConn) enqueue(p []byte) bool {
	select {
	case <-pc.done:
		return false
	default:
	}
	select {
	case pc.q <- p:
		return true
	default:
		poolDrops.Add(1)
		return false
	}
}

// serve runs the writer in a goroutine and the reader inline until the connection dies.
func (pc *poolConn) serve(wg *sync.WaitGroup, push func([]byte) bool) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		pc.writeLoop()
	}()
	pc.readLoop(push)
	pc.fail()
}

func (pc *poolConn) writeLoop() {
	bw := bufio.NewWriterSize(pc.c, poolBufSize)
	var hdr [2]byte
	for {
		select {
		case <-pc.done:
			return
		case p := <-pc.q:
			for { // batch: flush only when the queue runs dry
				binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
				if _, err := bw.Write(hdr[:]); err != nil {
					pc.fail()
					return
				}
				if _, err := bw.Write(p); err != nil {
					pc.fail()
					return
				}
				select {
				case p = <-pc.q:
					continue
				default:
				}
				break
			}
			if err := bw.Flush(); err != nil {
				pc.fail()
				return
			}
		}
	}
}

func (pc *poolConn) readLoop(push func([]byte) bool) {
	br := bufio.NewReaderSize(pc.c, poolBufSize)
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > poolMaxFrame {
			return
		}
		p := make([]byte, n) // fresh: Recv's slice stays valid until its next call
		if _, err := io.ReadFull(br, p); err != nil {
			return
		}
		if !push(p) {
			return
		}
	}
}

// leastQueued picks the live conn with the shortest queue; start rotates so ties spread.
func leastQueued(conns []*poolConn, start int) *poolConn {
	var best *poolConn
	bl := 1 << 30
	for i := range conns {
		pc := conns[(start+i)%len(conns)]
		if pc == nil {
			continue
		}
		if l := len(pc.q); l < bl {
			best, bl = pc, l
		}
	}
	return best
}

// ---------------------------------------------------------------- client

// PoolDialFunc opens one raw connection to the server (plain TCP or TLS).
type PoolDialFunc func(ctx context.Context) (net.Conn, error)

// TCPPoolClient is the client PacketIO over a pool of framed connections. The lane is ignored.
type TCPPoolClient struct {
	dial   func(ctx context.Context, slot int) (net.Conn, error)
	tlsFn  func() (string, string, bool) // TLS fingerprint, mode and ECH state, nil for non-TLS carriers
	ps     *peerSet
	peer   poolAddr
	remIP  atomic.Value // string: remote IP of the newest connection
	id     [8]byte
	slots  []atomic.Pointer[poolConn]
	rx     chan []byte
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	rr     atomic.Uint32
	once   sync.Once

	maxBackoff atomic.Int64               // cap of the redial backoff in ns (0: poolBackoffMax)
	logf       atomic.Pointer[dialLogger] // optional, see SetDialLog
	logMu      sync.Mutex
	lastLog    time.Time // last failure line
	failing    bool      // a failure was logged and no connection came up since
}

// NewTCPPoolClient dials conns (0 = DefaultPoolConns) TCP connections to host:port in the background; Send drops
// until the first one is up, which the session treats as loss.
//
// peer may hold several comma-separated addresses: slot i dials address i%n (see peerSet).
func NewTCPPoolClient(peer string, conns int) (*TCPPoolClient, error) {
	addrs, err := SplitPeers(peer)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return newSlotClient(addrs, conns, func(ctx context.Context, addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	})
}

// newSlotClient is a pool client whose slots spread over addrs; dial opens one connection to one address. A slot
// tries its home address first, then the others at once, and the pool's redial backoff only applies when all failed.
func newSlotClient(addrs []string, conns int, dial func(ctx context.Context, addr string) (net.Conn, error)) (*TCPPoolClient, error) {
	ps := newPeerSet(addrs)
	c, err := newSlotPoolClient(func(ctx context.Context, slot int) (net.Conn, error) {
		var last error
		for _, i := range ps.order(slot) {
			if ctx.Err() != nil {
				break
			}
			conn, err := dial(ctx, addrs[i])
			ps.mark(i, err == nil)
			if err == nil {
				return conn, nil
			}
			last = err
		}
		if last == nil {
			last = ctx.Err()
		}
		return nil, last
	}, conns)
	if c != nil {
		c.ps = ps
	}
	return c, err
}

func newPoolClient(dial PoolDialFunc, conns int) (*TCPPoolClient, error) {
	return newSlotPoolClient(func(ctx context.Context, _ int) (net.Conn, error) { return dial(ctx) }, conns)
}

// TLSInfo reports the TLS fingerprint in use and whether the newest connection used ECH (ok false: not a TLS carrier).
func (c *TCPPoolClient) TLSInfo() (fp, mode string, ech bool, ok bool) {
	if c.tlsFn == nil {
		return "", "", false, false
	}
	fp, mode, ech = c.tlsFn()
	return fp, mode, ech, true
}

// Edges reports the health of each peer address (nil for a client built without addresses).
func (c *TCPPoolClient) Edges() []EdgeStat {
	if c.ps == nil {
		return nil
	}
	return c.ps.edges()
}

func newSlotPoolClient(dial func(ctx context.Context, slot int) (net.Conn, error), conns int) (*TCPPoolClient, error) {
	if conns <= 0 {
		conns = DefaultPoolConns
	}
	if conns > poolMaxConns {
		conns = poolMaxConns
	}
	c := &TCPPoolClient{dial: dial, slots: make([]atomic.Pointer[poolConn], conns),
		rx: make(chan []byte, poolRxQueue), done: make(chan struct{})}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if _, err := crand.Read(c.id[:]); err != nil {
		return nil, err
	}
	c.peer = poolAddr{key: "server"}
	for i := range c.slots {
		c.wg.Add(1)
		go c.slotLoop(i)
	}
	return c, nil
}

const (
	poolBackoffMax = 3 * time.Second
	poolLogEvery   = 5 * time.Minute
)

type dialLogger struct {
	name string
	f    func(string, ...any)
}

// SetDialLog makes the client report failed dials: the first one, then at most one per few minutes (all slots
// together), and a line when a connection comes up again. name tags the lines (the carrier). Safe at any time.
func (c *TCPPoolClient) SetDialLog(name string, f func(string, ...any)) {
	if f != nil {
		c.logf.Store(&dialLogger{name, f})
	}
}

// SetMaxBackoff caps the redial backoff (default 3 s); a dialer whose far end may simply not be listening wants
// longer, so it neither hammers the peer nor fills the log.
func (c *TCPPoolClient) SetMaxBackoff(d time.Duration) { c.maxBackoff.Store(int64(d)) }

func (c *TCPPoolClient) backoffCap() time.Duration {
	if n := c.maxBackoff.Load(); n > 0 {
		return time.Duration(n)
	}
	return poolBackoffMax
}

func (c *TCPPoolClient) noteFail(err error) {
	l := c.logf.Load()
	if l == nil {
		return
	}
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if now := time.Now(); !c.failing || now.Sub(c.lastLog) >= poolLogEvery {
		c.lastLog = now
		c.failing = true
		l.f("%s: cannot connect (%v); retrying with backoff, next report in %v", l.name, err, poolLogEvery)
	}
}

func (c *TCPPoolClient) noteUp() {
	l := c.logf.Load()
	if l == nil {
		return
	}
	c.logMu.Lock()
	was := c.failing
	c.failing = false
	c.logMu.Unlock()
	if was {
		l.f("%s: connected", l.name)
	}
}

func (c *TCPPoolClient) peerAddr() poolAddr {
	a := c.peer
	a.ip, _ = c.remIP.Load().(string)
	return a
}

func (c *TCPPoolClient) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.done:
		return false
	}
}

func (c *TCPPoolClient) push(p []byte) bool {
	select {
	case c.rx <- p:
		return true
	case <-c.done:
		return false
	}
}

func (c *TCPPoolClient) slotLoop(i int) {
	defer c.wg.Done()
	backoff := 100 * time.Millisecond
	for {
		select {
		case <-c.done:
			return
		default:
		}
		conn, err := c.dial(c.ctx, i)
		if err == nil {
			conn.SetWriteDeadline(time.Now().Add(poolHelloWait))
			_, err = conn.Write(c.id[:])
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				conn.Close()
			}
		}
		if err != nil {
			c.noteFail(err)
			if !c.sleep(backoff) {
				return
			}
			backoff = min(backoff*2, c.backoffCap())
			continue
		}
		c.noteUp()
		if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			c.remIP.Store(ra.IP.String())
		} else if conn.RemoteAddr() != nil {
			c.remIP.Store(addrIP(conn.RemoteAddr()))
		}
		pc := newPoolConn(conn)
		c.slots[i].Store(pc)
		select { // Close may have swept the slots just before the Store
		case <-c.done:
			pc.fail()
		default:
		}
		t0 := time.Now()
		pc.serve(&c.wg, c.push)
		c.slots[i].Store(nil)
		if time.Since(t0) > time.Second {
			backoff = 100 * time.Millisecond
		}
		if !c.sleep(backoff) {
			return
		}
		backoff = min(backoff*2, c.backoffCap())
	}
}

func (c *TCPPoolClient) Send(p []byte, path int) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	conns := make([]*poolConn, len(c.slots))
	for i := range c.slots {
		conns[i] = c.slots[i].Load()
	}
	if pc := leastQueued(conns, int(c.rr.Add(1))); pc != nil {
		pc.enqueue(append([]byte(nil), p...)) // full queue: drop, the session repairs it
	}
	return nil
}

func (c *TCPPoolClient) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-c.rx:
		return p, 0, c.peerAddr(), nil
	case <-c.done:
		return nil, 0, nil, net.ErrClosed
	}
}

// Conns reports how many pool connections are currently up.
func (c *TCPPoolClient) Conns() int {
	n := 0
	for i := range c.slots {
		if c.slots[i].Load() != nil {
			n++
		}
	}
	return n
}

func (c *TCPPoolClient) SetPeer(net.Addr) {}

func (c *TCPPoolClient) Profile() Profile { return poolProfile }

func (c *TCPPoolClient) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.cancel()
		for i := range c.slots {
			if pc := c.slots[i].Load(); pc != nil {
				pc.fail()
			}
		}
		c.wg.Wait()
	})
	return nil
}

// ---------------------------------------------------------------- server

// TCPPoolServer is the server RawIO: one listener, many pools. Recv's src and SendTo's dst are poolAddr values.
type TCPPoolServer struct {
	ln    net.Listener
	rx    chan rxPkt
	done  chan struct{}
	wg    sync.WaitGroup
	rr    atomic.Uint32
	once  sync.Once
	mu    sync.Mutex
	pools map[string]map[*poolConn]struct{}
	all   map[net.Conn]struct{} // every accepted conn, so Close also reaches ones still in their hello
	merge atomic.Bool           // reverse mode: every conn joins one pool whatever its hello id says
}

// NewTCPPoolServer listens on addr (":4443").
func NewTCPPoolServer(addr string) (*TCPPoolServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newPoolServer(ln), nil
}

func newPoolServer(ln net.Listener) *TCPPoolServer {
	s := &TCPPoolServer{ln: ln, rx: make(chan rxPkt, poolRxQueue), done: make(chan struct{}),
		pools: map[string]map[*poolConn]struct{}{}, all: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

// Addr is the bound address (useful with port 0).
func (s *TCPPoolServer) Addr() net.Addr { return s.ln.Addr() }

func (s *TCPPoolServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(50 * time.Millisecond) // transient (EMFILE...): do not spin
			continue
		}
		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			c.Close()
			return
		default:
		}
		s.all[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *TCPPoolServer) handle(c net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.all, c)
		s.mu.Unlock()
	}()
	c.SetReadDeadline(time.Now().Add(poolHelloWait)) // also bounds a TLS handshake
	var id [8]byte
	if _, err := io.ReadFull(c, id[:]); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	pc := newPoolConn(c)
	key := string(id[:])
	if s.merge.Load() {
		key = reverseKey
	}
	if !s.add(key, pc) {
		pc.fail()
		return
	}
	src := poolAddr{key: key, ip: addrIP(c.RemoteAddr())}
	pc.serve(&s.wg, func(p []byte) bool {
		select {
		case s.rx <- rxPkt{p: p, src: src}:
			return true
		case <-s.done:
			return false
		}
	})
	s.remove(key, pc)
}

func (s *TCPPoolServer) add(key string, pc *poolConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	set := s.pools[key]
	if set == nil {
		if len(s.pools) >= poolMaxPools {
			return false
		}
		set = map[*poolConn]struct{}{}
		s.pools[key] = set
	}
	if len(set) >= poolMaxConns {
		return false
	}
	set[pc] = struct{}{}
	return true
}

func (s *TCPPoolServer) remove(key string, pc *poolConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.pools[key]; set != nil {
		delete(set, pc)
		if len(set) == 0 {
			delete(s.pools, key)
		}
	}
}

func (s *TCPPoolServer) Recv() ([]byte, int, net.Addr, error) {
	select {
	case r := <-s.rx:
		return r.p, 0, r.src, nil
	case <-s.done:
		return nil, 0, nil, net.ErrClosed
	}
}

func (s *TCPPoolServer) SendTo(p []byte, lane int, dst net.Addr) error {
	a, ok := dst.(poolAddr)
	if !ok {
		return net.ErrClosed
	}
	s.mu.Lock()
	conns := make([]*poolConn, 0, len(s.pools[a.key]))
	for pc := range s.pools[a.key] {
		conns = append(conns, pc)
	}
	s.mu.Unlock()
	if pc := leastQueued(conns, int(s.rr.Add(1))); pc != nil {
		pc.enqueue(append([]byte(nil), p...))
	}
	return nil // no live conn or full queue: dropped, the session repairs it
}

func (s *TCPPoolServer) Profile() Profile { return poolProfile }

// Pools and Conns report the live pool and connection counts.
func (s *TCPPoolServer) Pools() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pools)
}

func (s *TCPPoolServer) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, set := range s.pools {
		n += len(set)
	}
	return n
}

func (s *TCPPoolServer) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		close(s.done)
		s.mu.Unlock()
		s.ln.Close()
		s.mu.Lock()
		for c := range s.all {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return nil
}
