package wat

import (
	"net"
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// simHub is one server socket with several clients behind it, each with its own lossy up and down link.
type simHub struct {
	in    chan hubPkt
	mu    sync.Mutex
	done  chan struct{}
	downs map[string]*simDir
}

type hubPkt struct {
	p    []byte
	src  strAddr
	lane int
}

type strAddr string

func (a strAddr) Network() string { return "sim" }
func (a strAddr) String() string  { return string(a) }

func (h *simHub) Recv() ([]byte, int, net.Addr, error) {
	select {
	case r := <-h.in:
		return r.p, r.lane, r.src, nil
	case <-h.quit():
		return nil, 0, nil, io.EOF
	}
}

func (h *simHub) quit() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	return h.done
}

func (h *simHub) SendTo(p []byte, lane int, dst net.Addr) error {
	h.mu.Lock()
	d := h.downs[dst.String()]
	h.mu.Unlock()
	if d != nil {
		d.send(p)
	}
	return nil
}

// Close ends the current server's Recv; the next server starts with a fresh channel.
func (h *simHub) Close() error {
	h.mu.Lock()
	if h.done != nil {
		close(h.done)
		h.done = nil
	}
	h.mu.Unlock()
	return nil
}

// client returns a PacketIO for client `name` plus its closer.
func (h *simHub) client(name string, loss float64, delay time.Duration, bps float64, seed int64) PacketIO {
	up := newSimDir(loss, delay, bps, 100*time.Millisecond, seed)
	down := newSimDir(loss, delay, bps, 100*time.Millisecond, seed+1)
	h.mu.Lock()
	h.downs[name] = down
	h.mu.Unlock()
	go func() {
		for p := range up.out {
			h.in <- hubPkt{p, strAddr(name), 0}
		}
	}()
	return &simIO{up, down, make(chan struct{}), sync.Once{}}
}

func newHub(t *testing.T) (*simHub, *Server) {
	h := &simHub{in: make(chan hubPkt, 1<<16), downs: map[string]*simDir{}}
	srv := NewServer(Config{Key: []byte("hub-key")}, h)
	srv.IdleTimeout = 3 * time.Second
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() { io.Copy(st, st); st.CloseWrite() }()
				}
			}(s)
		}
	}()
	t.Cleanup(srv.Close)
	return h, srv
}

func echoOnce(t *testing.T, cli *Session, n int, seed byte) {
	t.Helper()
	data := pattern(n, seed)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(data); st.CloseWrite() }()
	got := make(chan []byte, 1)
	go func() { b, _ := readAll(st); got <- b }()
	select {
	case b := <-got:
		if !bytes.Equal(b, data) {
			t.Fatalf("echo mismatch: got %d want %d", len(b), n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("echo timeout")
	}
}

// Two client processes on the same key at once (the two slots of a handover) must not disturb each other.
func TestTwoClientsSameKey(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a", 0.02, 20*time.Millisecond, 10e6, 10))
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("b", 0.02, 20*time.Millisecond, 10e6, 20))
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	for i, c := range []*Session{a, b} {
		wg.Add(1)
		go func(i int, c *Session) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				echoOnce(t, c, 600000, byte(10*i+j))
			}
		}(i, c)
	}
	wg.Wait()
	if n := srv.Sessions(); n != 2 {
		t.Fatalf("server has %d sessions, want 2", n)
	}
}

// A client that restarts within two seconds is a new session; the old one expires on its own, nothing hangs.
func TestClientRestart(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a1", 0.02, 20*time.Millisecond, 10e6, 30))
	echoOnce(t, a, 200000, 1)
	a.Close() // killed without a goodbye
	time.Sleep(2 * time.Second)
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("a2", 0.02, 20*time.Millisecond, 10e6, 40))
	defer b.Close()
	for j := 0; j < 3; j++ { // stream ids restart at 1 in the new process: must not collide with the old one's
		echoOnce(t, b, 300000, byte(j+5))
	}
	time.Sleep(6 * time.Second)
	if n := srv.Sessions(); n != 1 {
		t.Fatalf("server still holds %d sessions after the old one went idle, want 1", n)
	}
}

// The server's cumulative counters must not go backwards when a client session closes: the stats log subtracts
// the previous total, and a smaller total wrapped to ~1.8e19 ("out=18446744073709551594").
func TestServerStatsMonotonicAfterSessionCloses(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4}, h.client("m1", 0, 10*time.Millisecond, 10e6, 50))
	echoOnce(t, a, 200000, 3)
	before := srv.Stats()
	if before.PktsOut == 0 || before.PktsIn == 0 {
		t.Fatalf("no traffic counted: %+v", before)
	}
	a.Close()
	deadline := time.Now().Add(10 * time.Second)
	for srv.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if n := srv.Sessions(); n != 0 {
		t.Fatalf("session did not expire (%d left)", n)
	}
	after := srv.Stats()
	if after.PktsOut < before.PktsOut || after.PktsIn < before.PktsIn || after.BytesOut < before.BytesOut || after.BytesIn < before.BytesIn {
		t.Fatalf("totals went backwards after the session closed: before %+v after %+v", before, after)
	}
}

// A draining server serves its sessions to the end but takes no new ones.
func TestDrain(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, h.client("d1", 0, 10*time.Millisecond, 10e6, 50))
	defer a.Close()
	echoOnce(t, a, 100000, 2)
	srv.Drain()
	echoOnce(t, a, 100000, 3) // existing session keeps working
	b, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 2}, h.client("d2", 0, 10*time.Millisecond, 10e6, 60))
	defer b.Close()
	time.Sleep(500 * time.Millisecond)
	if n := srv.Sessions(); n != 1 {
		t.Fatalf("draining server has %d sessions, want 1", n)
	}
}

// The server process restarts (new boot id, no memory of any stream): the client must notice, drop its dead streams
// and carry on with new ones. Before the boot frame existed the old connections just hung.
func TestServerRestart(t *testing.T) {
	h, srv := newHub(t)
	a, _ := NewSession(Config{Key: []byte("hub-key"), Paths: 4, Logf: t.Logf}, h.client("r1", 0.01, 15*time.Millisecond, 10e6, 70))
	defer a.Close()
	echoOnce(t, a, 100000, 1)
	// a stream that is open while the server dies
	hang, _ := a.OpenStream()
	hang.Write([]byte("hello"))
	if _, err := io.ReadFull(hang, make([]byte, 5)); err != nil { // the old server echoes it
		t.Fatal(err)
	}
	srv.Close()
	time.Sleep(200 * time.Millisecond)
	srv2 := NewServer(Config{Key: []byte("hub-key"), Logf: t.Logf}, h)
	srv2.IdleTimeout = 5 * time.Second
	go func() {
		for s := range srv2.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() { io.Copy(st, st); st.CloseWrite() }()
				}
			}(s)
		}
	}()
	defer srv2.Close()
	done := make(chan error, 1)
	go func() { _, err := hang.Read(make([]byte, 10)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("old stream read succeeded after the server restarted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("old stream still hangs 10 s after the server restarted")
	}
	echoOnce(t, a, 200000, 2) // new streams on the same client session work
}
