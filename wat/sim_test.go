package wat

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// simDir is one direction of a lossy, delayed, rate-limited link with a 700 B size cap.
type simDir struct {
	mu       sync.Mutex
	loss     float64
	delay    time.Duration
	bps      float64
	maxQueue time.Duration
	free     time.Time
	q        chan simItem
	out      chan []byte
	rnd      *rand.Rand
	dropped  int
	sent     int
	recQ     bool            // record the queueing delay every packet met
	qd       []time.Duration // (recQ only)
}

type simItem struct {
	at time.Time
	p  []byte
}

func newSimDir(loss float64, delay time.Duration, bps float64, maxQueue time.Duration, seed int64) *simDir {
	d := &simDir{loss: loss, delay: delay, bps: bps, maxQueue: maxQueue,
		q: make(chan simItem, 1<<16), out: make(chan []byte, 1<<16), rnd: rand.New(rand.NewSource(seed))}
	go func() {
		for it := range d.q {
			if w := time.Until(it.at); w > 0 {
				time.Sleep(w)
			}
			select {
			case d.out <- it.p:
			default:
			}
		}
	}()
	return d
}

func (d *simDir) send(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent++
	now := time.Now()
	if len(p) > 700 {
		d.dropped++
		return
	}
	start := d.free
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > d.maxQueue {
		d.dropped++
		return
	}
	if d.recQ {
		d.qd = append(d.qd, start.Sub(now))
	}
	d.free = start.Add(time.Duration(float64(len(p)+28) / d.bps * float64(time.Second)))
	if d.rnd.Float64() < d.loss {
		d.dropped++
		return
	}
	d.q <- simItem{d.free.Add(d.delay), append([]byte(nil), p...)}
}

type simIO struct {
	tx, rx *simDir
	done   chan struct{}
	once   sync.Once
}

func (s *simIO) Send(p []byte, lane int) error { s.tx.send(p); return nil }
func (s *simIO) Recv() ([]byte, int, net.Addr, error) {
	select {
	case p := <-s.rx.out:
		return p, 0, nil, nil
	case <-s.done:
		return nil, 0, nil, io.EOF
	}
}
func (s *simIO) SetPeer(net.Addr) {}
func (s *simIO) Close() error     { s.once.Do(func() { close(s.done) }); return nil }

func newPair(t testing.TB, loss float64, delay time.Duration, bps float64, cfg Config) (cli, srv *Session, up, down *simDir) {
	up = newSimDir(loss, delay, bps, 100*time.Millisecond, 1)
	down = newSimDir(loss, delay, bps, 100*time.Millisecond, 2)
	key := []byte("test-key")
	cc, sc := cfg, cfg
	cc.Key, sc.Key = key, key
	cc.Server, sc.Server = false, true
	cc.SID, sc.SID = 0x1234567, 0x1234567
	cc.Paths = 4
	var err error
	cli, err = NewSession(cc, &simIO{up, down, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(sc, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(int64(seed)))
	r.Read(b)
	return b
}

func readAll(st *Stream) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, st)
	return buf.Bytes(), err
}

// Upload: client -> server, 2% loss, 20 ms one way, 10 MB/s link.
func TestUploadLossy(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	data := pattern(24<<20, 7)
	got := make(chan []byte, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			got <- nil
			return
		}
		b, _ := readAll(st)
		got <- b
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	t0 := time.Now()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case b := <-got:
		el := time.Since(t0)
		if sha256.Sum256(b) != sha256.Sum256(data) {
			t.Fatalf("data mismatch: got %d want %d bytes", len(b), len(data))
		}
		s := cli.Stats()
		t.Logf("upload %.1f MB/s in %v, retrans=%d rate=%.1fMB/s srtt=%v min=%v", float64(len(data))/el.Seconds()/1e6, el.Round(time.Millisecond), s.Retrans, s.RateBps/1e6, s.SRTT, s.MinRTT)
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
}

// Download: server -> client over the same link.
func TestDownloadLossy(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	data := pattern(24<<20, 9)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		st.Write(data)
		st.CloseWrite()
	}()
	st, _ := cli.OpenStream()
	st.Write([]byte{1})
	st.CloseWrite()
	t0 := time.Now()
	done := make(chan []byte, 1)
	go func() { b, _ := readAll(st); done <- b }()
	select {
	case b := <-done:
		el := time.Since(t0)
		if sha256.Sum256(b) != sha256.Sum256(data) {
			t.Fatalf("data mismatch: got %d want %d bytes", len(b), len(data))
		}
		s := srv.Stats()
		t.Logf("download %.1f MB/s in %v, retrans=%d rate=%.1fMB/s srtt=%v min=%v", float64(len(data))/el.Seconds()/1e6, el.Round(time.Millisecond), s.Retrans, s.RateBps/1e6, s.SRTT, s.MinRTT)
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
}

// 200 streams at once, each echoed through the server, mixed sizes.
func TestManyStreams(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(st, st); st.CloseWrite() }()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			size := 100 + (i%10)*30000
			data := pattern(size, byte(i))
			st, err := cli.OpenStream()
			if err != nil {
				t.Error(err)
				return
			}
			go func() { st.Write(data); st.CloseWrite() }()
			b, err := readAll(st)
			if err != nil || !bytes.Equal(b, data) {
				t.Errorf("stream %d: err=%v got %d want %d", i, err, len(b), len(data))
			}
		}(i)
	}
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(90 * time.Second):
		t.Fatal("timeout")
	}
}

// Small request/response latency while a bulk download is running: the interactive-first scheduler and the
// pacer's short queues should keep this near the link RTT (40 ms).
func TestInteractiveDuringBulk(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	bulk := pattern(64<<20, 3)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				hdr := make([]byte, 1)
				if _, err := io.ReadFull(st, hdr); err != nil {
					return
				}
				if hdr[0] == 'B' {
					st.Write(bulk)
					st.CloseWrite()
					return
				}
				st.Write(hdr)
				st.CloseWrite()
			}()
		}
	}()
	bs, _ := cli.OpenStream()
	bs.Write([]byte{'B'})
	bs.CloseWrite()
	go io.Copy(io.Discard, bs)
	time.Sleep(3 * time.Second) // let the bulk flow ramp up
	var lat []time.Duration
	for i := 0; i < 40; i++ {
		t0 := time.Now()
		st, _ := cli.OpenStream()
		st.Write([]byte{'x'})
		st.CloseWrite()
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
		time.Sleep(50 * time.Millisecond)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	s := srv.Stats()
	t.Logf("interactive during bulk: p50=%v p90=%v max=%v (server rate %.1f MB/s srtt=%v min=%v)", lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)-1], s.RateBps/1e6, s.SRTT, s.MinRTT)
	if lat[len(lat)/2] > 250*time.Millisecond {
		t.Fatalf("interactive latency too high: p50=%v", lat[len(lat)/2])
	}
}

func TestRejectsForeignKey(t *testing.T) {
	cli, srv, up, _ := newPair(t, 0, 5*time.Millisecond, 10e6, Config{})
	_ = cli
	// a packet sealed with another key must never create a stream
	other, _ := NewSession(Config{Key: []byte("other"), Paths: 1, SID: 0x1234567}, &simIO{up, newSimDir(0, 0, 1e6, time.Second, 5), make(chan struct{}), sync.Once{}})
	defer other.Close()
	st, _ := other.OpenStream()
	st.Write([]byte("hello"))
	time.Sleep(300 * time.Millisecond)
	srv.mu.Lock()
	n := len(srv.streams)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("server accepted %d streams from a foreign key", n)
	}
}
