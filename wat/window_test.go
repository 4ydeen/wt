package wat

import (
	"crypto/sha256"
	"testing"
	"time"
)

// oneStreamDown runs one server->client stream over a lossless 150 ms RTT link and returns its MB/s.
func oneStreamDown(t *testing.T, oldReceiver bool, mb int) float64 {
	cfg := Config{InitBps: 40e6, MaxBps: 40e6}
	cli, srv, _, _ := newPair(t, 0, 75*time.Millisecond, 40e6, cfg)
	cli.noWinTune = oldReceiver
	for _, x := range []*Session{cli, srv} { // an unsampled path assumes a 120 ms loss timer; a 150 ms RTT needs a first sample
		x.mu.Lock()
		x.cc.srtt, x.cc.rttvar = 150*time.Millisecond, 10*time.Millisecond
		x.mu.Unlock()
	}
	data := pattern(mb<<20, 5)
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
		mbps := float64(len(data)) / el.Seconds() / 1e6
		t.Logf("old=%v: %.1f MB/s in %v (4 MB/RTT = %.1f MB/s)", oldReceiver, mbps, el.Round(time.Millisecond), 4.194304/0.150)
		return mbps
	case <-time.After(90 * time.Second):
		t.Fatal("timeout")
	}
	return 0
}

// A receiver that auto-tunes its window lets one stream go well past 4 MB per RTT; a peer that never advertises
// more than the implicit 4 MB window keeps exactly the old limit (and still works with a new sender).
func TestStreamWindowAutoTune(t *testing.T) {
	old := oneStreamDown(t, true, 96)
	nw := oneStreamDown(t, false, 96)
	if raceBuild {
		return
	}
	if old > 4.194304/0.150*1.15 {
		t.Fatalf("old-peer stream exceeded its 4 MB window: %.1f MB/s", old)
	}
	if nw < old*1.3 {
		t.Fatalf("auto-tuned window did not help: %.1f vs %.1f MB/s", nw, old)
	}
}
