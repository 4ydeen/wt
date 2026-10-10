package wat

import (
	"io"
	"net"
	"sync"
	"time"
	"testing"
)

// memDir is a zero-delay, lossless one-way link with a fixed pool of buffers, so a benchmark over it measures the
// session code (seal, frames, acks, loss bookkeeping) and not the test link's own allocations. Like a real socket it
// copies on Send, and the slice Recv returns is valid until the next Recv.
type memDir struct {
	free chan []byte
	out  chan []byte
}

func newMemDir() *memDir {
	d := &memDir{free: make(chan []byte, 4096), out: make(chan []byte, 4096)}
	for i := 0; i < cap(d.free); i++ {
		d.free <- make([]byte, 0, 2048)
	}
	return d
}

type memIO struct {
	tx, rx *memDir
	prev   []byte
	retain bool // test hook: pretend to be a carrier that queues the slice
	done   chan struct{}
	once   sync.Once
}

func (m *memIO) Send(p []byte, lane int) error {
	select {
	case b := <-m.tx.free:
		select {
		case m.tx.out <- append(b[:0], p...):
		default:
			m.tx.free <- b
		}
	default: // link buffers exhausted: loss, which the session repairs
	}
	return nil
}

func (m *memIO) Recv() ([]byte, int, net.Addr, error) {
	if m.prev != nil {
		m.rx.free <- m.prev
		m.prev = nil
	}
	select {
	case p := <-m.rx.out:
		m.prev = p
		return p, 0, nil, nil
	case <-m.done:
		return nil, 0, nil, io.EOF
	}
}
func (m *memIO) SetPeer(net.Addr) {}
func (m *memIO) Close() error     { m.once.Do(func() { close(m.done) }); return nil }

func memPair(tb testing.TB, cfg Config) (cli, srv *Session) {
	a, b := newMemDir(), newMemDir()
	cfg.Key, cfg.SID = []byte("bench-key"), 0x1234567
	cfg.InitBps, cfg.MaxBps = 400e6, 400e6
	cc, sc := cfg, cfg
	sc.Server = true
	var err error
	if cli, err = NewSession(cc, &memIO{tx: a, rx: b, done: make(chan struct{})}); err != nil {
		tb.Fatal(err)
	}
	if srv, err = NewSession(sc, &memIO{tx: b, rx: a, done: make(chan struct{})}); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

// BenchmarkSessionBulk pushes b.N * 64 KiB through one stream of a client/server pair over the in-memory link.
// Profile it with:  go test -run xxx -bench SessionBulk -benchmem -cpuprofile cpu.out ./wat/ && go tool pprof -top wat.test cpu.out
func BenchmarkSessionBulk(b *testing.B) {
	cli, srv := memPair(b, Config{})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, st) }()
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	st.CloseWrite()
	// wait until the receiver has everything acked
	for {
		cli.mu.Lock()
		done := st.finAcked
		cli.mu.Unlock()
		if done {
			break
		}
		runtimeGosched()
	}
	b.StopTimer()
}

func runtimeGosched() { time.Sleep(200 * time.Microsecond) }

// memIO copies in Send, like a socket: the session may recycle its buffers.
func (m *memIO) CopiesOnSend() bool { return !m.retain }
