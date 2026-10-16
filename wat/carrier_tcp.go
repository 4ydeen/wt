package wat

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"slices"
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
	poolSlabMin   = 16 << 10 // a slab with less room than this left is replaced before the next read
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

// Send-side datagram buffers of the pool carriers are recycled (v2.3.0): Send copies into one and the connection's
// writer hands it back once bufio has taken the bytes. Two size classes cover the default 4096 MTU and -mtu 16384;
// anything else is allocated and left to the GC. Received datagrams are NOT recycled: doing so (handing the buffer
// back on the next Recv) cost 15-25 % of loopback wss download throughput in repeated A/B runs, with a channel free
// list and with sync.Pool alike, so readLoop keeps allocating a fresh slice per datagram.
const (
	pktSmall = 4096
	pktBig   = poolMaxMTU
)

var (
	pktPoolSmall = sync.Pool{New: func() any { return new([pktSmall]byte) }}
	pktPoolBig   = sync.Pool{New: func() any { return new([pktBig]byte) }}
)

// getPkt returns a buffer of length n, recycled when one of the size classes fits.
func getPkt(n int) []byte {
	switch {
	case n <= pktSmall:
		return pktPoolSmall.Get().(*[pktSmall]byte)[:n]
	case n <= pktBig:
		return pktPoolBig.Get().(*[pktBig]byte)[:n]
	}
	return make([]byte, n)
}

// putPkt hands a buffer from getPkt back; the caller must not touch it afterwards.
func putPkt(b []byte) {
	switch cap(b) {
	case pktSmall:
		pktPoolSmall.Put((*[pktSmall]byte)(b[:pktSmall]))
	case pktBig:
		pktPoolBig.Put((*[pktBig]byte)(b[:pktBig]))
	}
}

// poolConn is one framed connection with its own bounded send queue.
type poolConn struct {
	c     net.Conn
	q     chan []byte
	done  chan struct{}
	once  sync.Once
	wbusy atomic.Int64 // unix ns when the writer entered a socket write that has not returned yet, 0 when idle
	rx    atomic.Uint64 // datagrams received
	born  time.Time

	rxMark  uint64 // owned by the pool's health check (judgeSlow)
	lowWins int
}

// A pool connection whose socket write has been blocked this long is stalled: through a CDN, one edge connection can
// sit in TCP retransmit backoff for tens of seconds with megabytes queued while the others flow (field 2026-10-12:
// backoff 8, 5 MB Send-Q). Its own queue looks empty because the kernel holds the data, so leastQueued kept picking
// it and every packet sent there was lost for 400+ ms. Stalled conns are skipped while a healthy one exists, and
// closed (the client redials) once stuck for poolStallKill.
// PoolTCPCC is the TCP congestion control set on every pool socket (2.4.18, `tcp-cc`; "" keeps the kernel default).
// The kernel default (cubic) halves a connection's window on every loss, and on the Iran path random loss is not
// congestion. Field 2026-10-16 (reverse tcp, 8 conns, 40 ms): ~20 MB/s per tunnel, far below
// what one session moves on one core. BBR paces by measured bandwidth and RTT and does not back off on random loss.
// Local to each end: the sender of a direction decides, so set it on both.
var PoolTCPCC = "bbr"

var poolTCPCCInUse atomic.Pointer[string]

// PoolTCPCCInUse is the congestion control the last pool socket ended up with ("" = no pool socket yet / not Linux).
func PoolTCPCCInUse() string {
	if p := poolTCPCCInUse.Load(); p != nil {
		return *p
	}
	return ""
}

const (
	poolStall     = 300 * time.Millisecond
	poolStallKill = 5 * time.Second
	poolLowat     = 128 << 10
)

func newPoolConn(c net.Conn) *poolConn {
	if tc := rawTCP(c); tc != nil {
		tc.SetNoDelay(true)
		setNotsentLowat(tc, poolLowat) // a stalled conn must block its writer, not swallow megabytes
		if cc := setCongestion(tc, PoolTCPCC); cc != "" {
			poolTCPCCInUse.Store(&cc)
		}
	}
	return &poolConn{c: c, q: make(chan []byte, poolQueue), done: make(chan struct{}), born: time.Now()}
}

// The sender spreads datagrams evenly over its pool connections, so each one should deliver about the same number.
// Through a CDN, one connection's far leg can slow down while the sender's own socket to the edge stays clean: the
// edge buffers, everything sent on that connection arrives seconds late, and the session resends it (field
// 2026-10-12, 2.4.6 after ~3 h: about half of all packets resent with zero real loss, and the tunnel fell to ~1 MB/s).
// The sender cannot see it, but the receiver can: once a second each end compares what every connection delivered,
// and closes one that delivered under half the typical (upper-quartile) count for poolSlowWins seconds in a row. The
// client redials it, through a fresh path. Works with any peer version: it only closes connections.
const (
	poolSlowEvery = time.Second
	poolSlowWins  = 3
	poolSlowMin   = 24 // datagrams per connection per window, on average, before anything is judged
	poolSlowAge   = 3 * time.Second
)

var poolSlowKills atomic.Int64

// PoolSlowKills is how many pool connections this process closed for delivering far below their share.
func PoolSlowKills() int64 { return poolSlowKills.Load() }

// judgeSlow takes one window's delivery counts and returns the connection to close, if any. Only the pool's health
// check calls it, so rxMark and lowWins need no lock.
func judgeSlow(conns []*poolConn, now time.Time) *poolConn {
	type cnt struct {
		pc *poolConn
		d  uint64
	}
	var cs []cnt
	var total uint64
	for _, pc := range conns {
		if pc == nil {
			continue
		}
		v := pc.rx.Load()
		d := v - pc.rxMark
		pc.rxMark = v
		if now.Sub(pc.born) < poolSlowAge {
			pc.lowWins = 0
			continue
		}
		cs = append(cs, cnt{pc, d})
		total += d
	}
	if len(cs) < 3 || total < uint64(poolSlowMin*len(cs)) {
		for _, c := range cs {
			c.pc.lowWins = 0
		}
		return nil
	}
	ds := make([]uint64, len(cs))
	for i, c := range cs {
		ds[i] = c.d
	}
	slices.Sort(ds)
	ref := ds[len(ds)*3/4]
	var worst *poolConn
	var wd uint64
	for _, c := range cs {
		if 2*c.d >= ref {
			c.pc.lowWins = 0
			continue
		}
		if c.pc.lowWins++; c.pc.lowWins >= poolSlowWins && (worst == nil || c.d < wd) {
			worst, wd = c.pc, c.d
		}
	}
	if worst != nil {
		worst.lowWins = 0
	}
	return worst
}

// rawTCP finds the TCP socket under the TLS / WebSocket / gRPC / fragmenting wrappers (nil for an HTTP/2 stream).
func rawTCP(c net.Conn) *net.TCPConn {
	for i := 0; i < 8 && c != nil; i++ {
		switch x := c.(type) {
		case *net.TCPConn:
			return x
		case *wsConn:
			c = x.Conn
		case *grpcConn:
			c = x.Conn
		case *fragConn:
			c = x.Conn
		case interface{ NetConn() net.Conn }:
			c = x.NetConn()
		default:
			return nil
		}
	}
	return nil
}

// stalledFor is how long the current socket write has been blocked (0 when the writer is not inside one).
func (pc *poolConn) stalledFor(now int64) time.Duration {
	if t := pc.wbusy.Load(); t != 0 {
		return time.Duration(now - t)
	}
	return 0
}

// timedWriter marks the poolConn busy for the duration of every socket write.
type timedWriter struct{ pc *poolConn }

func (w timedWriter) Write(b []byte) (int, error) {
	w.pc.wbusy.Store(time.Now().UnixNano())
	n, err := w.pc.c.Write(b)
	w.pc.wbusy.Store(0)
	return n, err
}

// poolConnDeaths counts pool connections that went down, process-wide. Whatever was queued on one or still in its
// socket is gone, so a session polls this and resends its old unacked packets at once (Session.timers) instead of
// waiting out the loss timer.
var poolConnDeaths atomic.Uint64

// PoolConnDeaths is how many pool connections closed or failed in this process.
func PoolConnDeaths() uint64 { return poolConnDeaths.Load() }

func (pc *poolConn) fail() {
	pc.once.Do(func() {
		poolConnDeaths.Add(1)
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
		putPkt(p)
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
	bw := bufio.NewWriterSize(timedWriter{pc}, poolBufSize)
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
				_, err := bw.Write(p)
				putPkt(p) // bufio has copied it (or written it through)
				if err != nil {
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

// readLoop reads the connection into 64 KB slabs and hands out the datagrams as sub-slices of them (v2.4.0): no
// bufio copy and no allocation per datagram (one slab per ~16 datagrams). A slab is never reused: Recv's slice stays
// valid for as long as the session holds it. The unread tail of a full slab moves to the next one.
func (pc *poolConn) readLoop(push func([]byte) bool) {
	buf := make([]byte, poolBufSize)
	r, w := 0, 0
	for {
		if w-r < 2 {
			if n, ok := pc.fill(&buf, &r, &w, 2); !ok {
				_ = n
				return
			}
		}
		n := int(binary.BigEndian.Uint16(buf[r:]))
		if n == 0 || n > poolMaxFrame {
			return
		}
		if w-r < 2+n {
			if _, ok := pc.fill(&buf, &r, &w, 2+n); !ok {
				return
			}
		}
		p := buf[r+2 : r+2+n : r+2+n]
		r += 2 + n
		pc.rx.Add(1)
		if !push(p) {
			return
		}
	}
}

// fill reads until at least need bytes are buffered at buf[*r:*w], moving to a fresh slab when the current one has
// no room left for them (or is nearly full, so reads stay large).
func (pc *poolConn) fill(buf *[]byte, r, w *int, need int) (int, bool) {
	if len(*buf)-*r < need || len(*buf)-*w < poolSlabMin {
		nb := make([]byte, poolBufSize)
		*w = copy(nb, (*buf)[*r:*w])
		*buf, *r = nb, 0
	}
	for *w-*r < need {
		n, err := pc.c.Read((*buf)[*w:])
		*w += n
		if err != nil && *w-*r < need {
			return n, false
		}
	}
	return 0, true
}

// poolBacklog is the queue depth at which a pool counts as full: past it Send would soon drop.
const poolBacklog = poolQueue / 2

// backlogged reports whether even the least-queued usable conn already holds poolBacklog packets. Over a lossy path
// the pool's TCP connections stall in their own retransmits, their sockets stop taking data, and the queues fill;
// before 2.4.18 the session kept sending, Send dropped the overflow, and each drop came back as a "loss" ~400 ms later
// (field 2026-10-16, Kharej -> Iran: 61k such losses in 4x200 MB, ~20 MB/s where bare TCP did 78). Holding new data
// while the queues are full turns those drops into backpressure. No conn at all is not a backlog: the session keeps
// its old behaviour while the pool (re)connects.
func backlogged(conns []*poolConn) bool {
	now := time.Now().UnixNano()
	best, anyQ, n := 1<<30, 1<<30, 0
	for _, pc := range conns {
		if pc == nil {
			continue
		}
		n++
		l := len(pc.q)
		anyQ = min(anyQ, l)
		if pc.stalledFor(now) > poolStall {
			continue
		}
		best = min(best, l)
	}
	if n == 0 {
		return false
	}
	if best == 1<<30 { // every conn is stalled: judge by the shortest queue, as leastQueued does
		best = anyQ
	}
	return best >= poolBacklog
}

// leastQueued picks the live conn with the shortest queue; start rotates so ties spread.
func leastQueued(conns []*poolConn, start int) *poolConn {
	now := time.Now().UnixNano()
	var best, any *poolConn
	bl, al := 1<<30, 1<<30
	var stuck []*poolConn
	for i := range conns {
		pc := conns[(start+i)%len(conns)]
		if pc == nil {
			continue
		}
		l := len(pc.q)
		if l < al {
			any, al = pc, l
		}
		if d := pc.stalledFor(now); d > poolStall {
			if d > poolStallKill {
				stuck = append(stuck, pc)
			}
			continue
		}
		if l < bl {
			best, bl = pc, l
		}
	}
	if best == nil { // every conn is stalled: the whole path is slow, not one edge
		return any
	}
	for _, pc := range stuck { // a healthy conn exists: drop the stuck ones so the client redials them
		go pc.fail()
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

	keepSlow   atomic.Bool                // never close a connection for delivering below its share (SetKeepSlow)
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
	c.wg.Add(1)
	go c.healthLoop()
	return c, nil
}

// healthLoop closes a connection that delivers far below its share (see judgeSlow); its slot redials it.
func (c *TCPPoolClient) healthLoop() {
	defer c.wg.Done()
	t := time.NewTicker(poolSlowEvery)
	defer t.Stop()
	conns := make([]*poolConn, len(c.slots))
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			if c.keepSlow.Load() {
				continue
			}
			for i := range c.slots {
				conns[i] = c.slots[i].Load()
			}
			if pc := judgeSlow(conns, now); pc != nil {
				poolSlowKills.Add(1)
				pc.fail()
			}
		}
	}
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

// Send copies p, but the pool carriers deliberately do not declare CopiesOnSend: letting the session recycle its
// sealed buffers saved ~7 % of the pump's CPU yet cost about a third of single-session wss download throughput on
// loopback in repeated A/B runs (2.3.0 measurements), so the session keeps allocating them.
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
		pc.enqueue(append(getPkt(len(p))[:0], p...)) // full queue: drop, the session repairs it
	}
	return nil
}

// SetKeepSlow turns off the slow-connection check for a direct path (see TCPPoolServer.SetKeepSlow).
func (c *TCPPoolClient) SetKeepSlow(v bool) { c.keepSlow.Store(v) }

// Backlogged reports whether the pool's send queues are full (Backlogger).
func (c *TCPPoolClient) Backlogged() bool {
	conns := make([]*poolConn, len(c.slots))
	for i := range c.slots {
		conns[i] = c.slots[i].Load()
	}
	return backlogged(conns)
}

// Clone returns a new pool client to the same peer(s) with the same dial function, and with it the same TLS engine
// (fingerprint, ECH state and cache) and the same per-address health, but its own connections and its own random
// pool id, so the server sees an independent pool. The clone's slot i dials as slot i+slotOffset of the original
// would, which moves its starting edge on a multi-address -peer. (-sessions N, client only, 2.3.0.)
func (c *TCPPoolClient) Clone(slotOffset int) (*TCPPoolClient, error) {
	n, err := newSlotPoolClient(func(ctx context.Context, slot int) (net.Conn, error) {
		return c.dial(ctx, slot+slotOffset)
	}, len(c.slots))
	if err != nil {
		return nil, err
	}
	n.ps, n.tlsFn = c.ps, c.tlsFn
	n.keepSlow.Store(c.keepSlow.Load())
	n.maxBackoff.Store(c.maxBackoff.Load())
	if l := c.logf.Load(); l != nil {
		n.logf.Store(l)
	}
	return n, nil
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
	keep  atomic.Bool           // never close a connection for delivering below its share (SetKeepSlow)
}

// SetKeepSlow turns off the slow-connection check (2.4.7) for a direct path (2.4.18). It exists for a CDN edge whose
// far leg slows down; on a direct but lossy path every connection's delivery swings with its own TCP retransmits
// (field 2026-10-16, Kharej -> Iran: 2 to 209 Mbit/s per connection in one sample), and closing one throws away
// everything queued on it.
func (s *TCPPoolServer) SetKeepSlow(v bool) { s.keep.Store(v) }

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
	s.wg.Add(2)
	go s.acceptLoop()
	go s.healthLoop()
	return s
}

// healthLoop closes, per pool, a connection that delivers far below its share (see judgeSlow); the client redials.
func (s *TCPPoolServer) healthLoop() {
	defer s.wg.Done()
	t := time.NewTicker(poolSlowEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			pools := make([][]*poolConn, 0, len(s.pools))
			for _, set := range s.pools {
				conns := make([]*poolConn, 0, len(set))
				for pc := range set {
					conns = append(conns, pc)
				}
				pools = append(pools, conns)
			}
			s.mu.Unlock()
			for _, cs := range pools {
				if s.keep.Load() {
					break
				}
				if pc := judgeSlow(cs, now); pc != nil {
					poolSlowKills.Add(1)
					pc.fail()
				}
			}
		}
	}
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
		pc.enqueue(append(getPkt(len(p))[:0], p...))
	}
	return nil // no live conn or full queue: dropped, the session repairs it
}

// BackloggedTo reports whether the pool behind dst has its send queues full (RawBacklogger).
func (s *TCPPoolServer) BackloggedTo(dst net.Addr) bool {
	a, ok := dst.(poolAddr)
	if !ok {
		return false
	}
	s.mu.Lock()
	conns := make([]*poolConn, 0, len(s.pools[a.key]))
	for pc := range s.pools[a.key] {
		conns = append(conns, pc)
	}
	s.mu.Unlock()
	return backlogged(conns)
}

// PoolDrops counts packets dropped because every pool queue was full (process-wide).
func PoolDrops() int64 { return poolDrops.Load() }

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
