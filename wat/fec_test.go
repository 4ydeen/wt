package wat

import (
	"bytes"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"
)

// Every possible single loss inside a random group is rebuilt byte-exactly and the data reaches the stream.
func TestFecReconstruct(t *testing.T) {
	snd, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	rnd := rand.New(rand.NewSource(5))
	for trial := 0; trial < 60; trial++ {
		n := 1 + rnd.Intn(fecMaxK)
		miss := rnd.Intn(n)
		sid := uint64(trial + 1)
		pn0 := uint64(10000 + trial*100)
		var want []byte
		var plains [][]byte
		off := 0
		for i := 0; i < n; i++ {
			d := pattern(1+rnd.Intn(500), byte(trial*7+i))
			want = append(want, d...)
			typ := byte(frStream)
			if i == n-1 {
				typ = frStreamFin
			}
			p := append([]byte{typ}, appendUv(appendUv(appendUv(nil, sid), uint64(off)), uint64(len(d)))...)
			plains = append(plains, append(p, d...))
			off += len(d)
		}
		snd.mu.Lock()
		snd.cc.tokens = 1e9
		snd.fec.loss = 0.001 // k = 16: the whole group is covered
		for i, p := range plains {
			snd.fecNoteSent(pn0+uint64(i*2), p) // gaps in the pn sequence, like acks-only packets in between
		}
		snd.nextPN = pn0 + uint64(2*n) // the parity pn must sit near the covered ones (replay window)
		o, ok := snd.fecDue(time.Now())
		snd.mu.Unlock()
		if !ok {
			t.Fatal("no parity built")
		}
		rcv.mu.Lock()
		for i, p := range plains {
			if i == miss {
				continue
			}
			pn := pn0 + uint64(i*2)
			rcv.rxAny, rcv.rxLargest = true, max(rcv.rxLargest, pn)
			rcv.rxRing[pn%rcv.replayWin] = pn + 1
			rcv.fecKeep(pn, p)
			rcv.parse(p, time.Now())
		}
		rcv.mu.Unlock()
		rcv.handle(o.p, 0, nil)
		st, err := rcv.Accept()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := readAll(st)
		if !bytes.Equal(got, want) {
			t.Fatalf("trial %d (n=%d miss=%d): rebuilt stream differs (%d vs %d bytes)", trial, n, miss, len(got), len(want))
		}
	}
	if r := rcv.Stats().FecRecovered; r != 60 {
		t.Fatalf("recovered %d of 60", r)
	}
	if snd.Stats().FecSent != 60 {
		t.Fatalf("sent %d parity packets", snd.Stats().FecSent)
	}
}

// Two missing packets in one group cannot be rebuilt (and must not corrupt anything).
func TestFecTwoMissing(t *testing.T) {
	snd, rcv, _, _ := newPair(t, 0, time.Millisecond, 10e6, Config{FEC: true})
	var plains [][]byte
	snd.mu.Lock()
	snd.cc.tokens = 1e9
	for i := 0; i < 4; i++ {
		p := append([]byte{frStream, 1, byte(i * 10), 10}, pattern(10, byte(i))...)
		plains = append(plains, p)
		snd.fecNoteSent(uint64(500+i), p)
	}
	snd.nextPN = 504
	o, _ := snd.fecDue(time.Now())
	snd.mu.Unlock()
	rcv.mu.Lock()
	for _, i := range []int{0, 3} {
		pn := uint64(500 + i)
		rcv.rxAny, rcv.rxLargest = true, 503
		rcv.rxRing[pn%rcv.replayWin] = pn + 1
		rcv.fecKeep(pn, plains[i])
	}
	rcv.mu.Unlock()
	rcv.handle(o.p, 0, nil)
	if r := rcv.Stats().FecRecovered; r != 0 {
		t.Fatalf("recovered %d with two packets missing", r)
	}
}

// k shrinks as the observed loss rises.
func TestFecAdaptiveK(t *testing.T) {
	f := newFec()
	for i := 0; i < 5000; i++ {
		f.onAck()
	}
	if f.k() != fecMaxK {
		t.Fatalf("clean link: k=%d", f.k())
	}
	for i := 0; i < 5000; i++ {
		if i%10 == 0 {
			f.onLoss()
		} else {
			f.onAck()
		}
	}
	if f.k() != fecMinK {
		t.Fatalf("10%% loss: k=%d", f.k())
	}
}

// 3 flights per exchange, each a single small packet each way: a loss costs a PTO without FEC.
func fecExchanges(t *testing.T, fec bool, n int) (lat []time.Duration, cli, srv Stats) {
	c, s, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{FEC: fec})
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 200)
				for {
					if _, err := readFull(st, buf); err != nil {
						return
					}
					st.Write(buf)
				}
			}()
		}
	}()
	buf := make([]byte, 200)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		st, _ := c.OpenStream()
		for f := 0; f < 3; f++ {
			st.Write(pattern(200, byte(i)))
			if _, err := readFull(st, buf); err != nil {
				t.Error(err)
				return
			}
		}
		lat = append(lat, time.Since(t0))
		st.CloseWrite()
	}
	return lat, c.Stats(), s.Stats()
}

func readFull(st *Stream, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := st.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func pct(lat []time.Duration, p float64) time.Duration {
	l := append([]time.Duration(nil), lat...)
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return l[int(float64(len(l)-1)*p)]
}

func TestFecTailLatency(t *testing.T) {
	var wg sync.WaitGroup
	var off, on []time.Duration
	var onC, onS, offC, offS Stats
	wg.Add(2)
	go func() { defer wg.Done(); off, offC, offS = fecExchanges(t, false, 200) }()
	go func() { defer wg.Done(); on, onC, onS = fecExchanges(t, true, 200) }()
	wg.Wait()
	if len(off) != 200 || len(on) != 200 {
		t.Fatal("incomplete run")
	}
	p95off, p95on := pct(off, 0.95), pct(on, 0.95)
	t.Logf("200 x 3-flight exchanges at 2%% loss: p50 off=%v on=%v  p95 off=%v on=%v  p99 off=%v on=%v  fec sent=%d recovered=%d",
		pct(off, .5), pct(on, .5), p95off, p95on, pct(off, .99), pct(on, .99), onC.FecSent+onS.FecSent, onC.FecRecovered+onS.FecRecovered)
	if offC.FecSent+offS.FecSent != 0 {
		t.Fatal("fec off sent parity")
	}
	if onC.FecRecovered+onS.FecRecovered == 0 {
		t.Fatal("fec on recovered nothing")
	}
	if float64(p95on) > 0.8*float64(p95off) {
		t.Fatalf("p95 with fec %v is not >= 20%% below %v", p95on, p95off)
	}
}

func fecUpload(t *testing.T, fec bool) (float64, Stats) {
	cli, srv, _, _ := newPair(t, 0.02, 20*time.Millisecond, 10e6, Config{FEC: fec})
	data := pattern(24<<20, 7)
	got := make(chan int, 1)
	go func() {
		st, err := srv.Accept()
		if err != nil {
			got <- -1
			return
		}
		b, _ := readAll(st)
		got <- len(b)
	}()
	st, _ := cli.OpenStream()
	t0 := time.Now()
	go func() { st.Write(data); st.CloseWrite() }()
	select {
	case n := <-got:
		if n != len(data) {
			t.Fatalf("got %d bytes", n)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
	return float64(len(data)) / time.Since(t0).Seconds() / 1e6, cli.Stats()
}

func TestFecBulkThroughput(t *testing.T) {
	var off, on float64
	var st Stats
	for round := 0; round < 2; round++ { // interleaved, best of two: the sim is timing-noisy
		o, _ := fecUpload(t, false)
		n, s := fecUpload(t, true)
		off, on, st = max(off, o), max(on, n), s
	}
	t.Logf("bulk upload 2%% loss: off=%.2f MB/s on=%.2f MB/s, parity packets %d of %d", off, on, st.FecSent, st.PktsOut)
	if on < 0.95*off {
		t.Fatalf("fec bulk %.2f MB/s is more than 5%% below off %.2f", on, off)
	}
	if float64(st.FecSent) > 0.05*float64(st.PktsOut) {
		t.Fatalf("parity overhead %d of %d packets", st.FecSent, st.PktsOut)
	}
}
