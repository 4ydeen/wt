package wat

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// collect drains s.Datagrams() into a per-seq count until the session is done.
func collect(s *Session) (seen *sync.Map, n *atomic.Int64) {
	seen, n = &sync.Map{}, &atomic.Int64{}
	go func() {
		for {
			select {
			case d := <-s.Datagrams():
				if len(d.Data) >= 8 {
					c, _ := seen.LoadOrStore(binary.BigEndian.Uint64(d.Data), new(atomic.Int32))
					c.(*atomic.Int32).Add(1)
				}
				n.Add(1)
			case <-s.Done():
				return
			}
		}
	}()
	return
}

func dg(seq uint64, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

func dupes(m *sync.Map) (dup int) {
	m.Range(func(_, v any) bool {
		if v.(*atomic.Int32).Load() > 1 {
			dup++
		}
		return true
	})
	return
}

// Datagrams flow both ways over a 10% loss link; lost ones are gone for good (no duplicates, no repair).
func TestDgramBothWaysNotRetransmitted(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.10, 10*time.Millisecond, 10e6, Config{})
	cSeen, cN := collect(cli)
	sSeen, sN := collect(srv)
	const total = 2000
	var okC, okS int
	for i := 0; i < total; i++ {
		if cli.SendDatagram(7, 9000, dg(uint64(i), 200)) {
			okC++
		}
		if srv.SendDatagram(7, 9000, dg(uint64(i), 200)) {
			okS++
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond) // anything still in flight lands; a repair would also show by now
	for name, v := range map[string][3]int64{"to server": {int64(okC), sN.Load(), int64(dupes(sSeen))}, "to client": {int64(okS), cN.Load(), int64(dupes(cSeen))}} {
		if v[1] < v[0]*75/100 || v[1] >= v[0] {
			t.Errorf("%s: sent %d got %d, want ~90%% (loss must not be repaired)", name, v[0], v[1])
		}
		if v[2] != 0 {
			t.Errorf("%s: %d duplicated datagrams", name, v[2])
		}
	}
	st := cli.Stats()
	t.Logf("client: sent=%d recv=%d dropq=%d inflight=%d retrans=%d", st.DgramSent, st.DgramRecv, st.DgramDropQueue, st.Inflight, st.Retrans)
	if st.Inflight > 100000 {
		t.Errorf("inflight leaked: %d", st.Inflight)
	}
}

// A datagram flood in both directions must not stop a bulk stream transfer.
func TestDgramFloodBulkStillCompletes(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	collect(cli)
	collect(srv)
	data := pattern(6<<20, 5)
	got := make(chan [32]byte, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		h := sha256.New()
		io.Copy(h, st)
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		got <- sum
	}()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, s := range []*Session{cli, srv} {
		wg.Add(1)
		go func(s *Session) {
			defer wg.Done()
			p := make([]byte, 500)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				s.SendDatagram(1, 1000, p)
				if i%64 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(s)
	}
	t0 := time.Now()
	st, _ := cli.OpenStream()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case sum := <-got:
		if sum != sha256.Sum256(data) {
			t.Fatal("stream corrupted")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("bulk transfer starved by the datagram flood")
	}
	close(stop)
	wg.Wait()
	cs := cli.Stats()
	t.Logf("6 MB during flood in %v; client dgram sent=%d dropq=%d", time.Since(t0).Round(time.Millisecond), cs.DgramSent, cs.DgramDropQueue)
	if cs.DgramDropQueue == 0 {
		t.Error("flood never hit the queue bound; test proves nothing")
	}
}

// A full queue drops (and counts) without blocking the caller; oversize datagrams are dropped, not fragmented.
func TestDgramQueueFullAndOversize(t *testing.T) {
	cli, _, up, _ := newPair(t, 0, 0, 1e6, Config{})
	up.mu.Lock()
	up.loss = 1 // nothing is delivered; the point is only the sender's queue
	up.mu.Unlock()
	t0 := time.Now()
	acc := 0
	for i := 0; i < 5000; i++ {
		if cli.SendDatagram(1, 80, make([]byte, 600)) {
			acc++
		}
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("SendDatagram blocked: %v", d)
	}
	st := cli.Stats()
	if st.DgramDropQueue == 0 || acc+int(st.DgramDropQueue)+int(st.DgramDropSize) != 5000 {
		t.Fatalf("accounting off: accepted=%d dropq=%d dropsize=%d", acc, st.DgramDropQueue, st.DgramDropSize)
	}
	if !cli.SendDatagram(1, 80, make([]byte, cli.MaxDatagram())) && cli.Stats().DgramDropQueue == st.DgramDropQueue {
		t.Fatal("MaxDatagram payload rejected for a reason other than a full queue")
	}
	before := cli.Stats().DgramDropSize
	if cli.SendDatagram(1<<62, 65535, make([]byte, 700)) {
		t.Fatal("oversize datagram accepted")
	}
	if cli.Stats().DgramDropSize != before+1 {
		t.Fatal("oversize drop not counted")
	}
}

// Interactive streams keep their latency bound while a datagram flood runs.
func TestInteractiveDuringDgramFlood(t *testing.T) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{})
	collect(cli)
	collect(srv)
	go func() {
		for {
			st, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 1)
				if _, err := io.ReadFull(st, b); err == nil {
					st.Write(b)
					st.CloseWrite()
				}
			}()
		}
	}()
	stop := make(chan struct{})
	defer close(stop)
	for _, s := range []*Session{cli, srv} {
		go func(s *Session) {
			p := make([]byte, 500)
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				s.SendDatagram(1, 1000, p)
				if i%64 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(s)
	}
	time.Sleep(2 * time.Second)
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
	t.Logf("interactive during dgram flood: p50=%v p90=%v max=%v", lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)-1])
	if lat[len(lat)/2] > 250*time.Millisecond {
		t.Fatalf("interactive latency too high: p50=%v", lat[len(lat)/2])
	}
}

