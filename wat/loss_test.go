package wat

import (
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReliableLossV2 pins the 2.4.9 reliable rule: spurious retransmits (declared lost, later acked) are removed from
// the congestion signal and stretch the loss timer; genuine loss cuts gently with a creeping ceiling, never to the floor.
func TestReliableLossV2(t *testing.T) {
	if !relV2 {
		t.Skip("v1 forced")
	}
	// a burst of losses that all turn out spurious: no rate cut, and the loss timer stretches
	c := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	c.reliable, c.minRate, c.hardMin = true, 8e6, 8e6
	base := c.lossTime()
	for i := 0; i < 20; i++ {
		c.sentN, c.lostN, c.spuriousN = 200, 30, 30
		if c.reliableLoss(c.sentN, c.lostN) {
			t.Fatal("spurious retransmits were read as congestion")
		}
		c.sentN, c.lostN, c.spuriousN = 0, 0, 0
	}
	if c.rate != 10e6 {
		t.Fatalf("rate moved on spurious loss: %.2f", c.rate/1e6)
	}
	if c.lossTime() <= base {
		t.Fatalf("loss timer did not stretch: %v vs %v", c.lossTime(), base)
	}
	// genuine loss (nothing spurious): a gentle multiplicative cut, floored at hardMin, with a ceiling above it
	g := newCC(40e6, 0.1e6, 80e6, 8*time.Millisecond)
	g.reliable, g.minRate, g.hardMin = true, 8e6, 8e6
	g.sentN, g.lostN, g.spuriousN = 200, 30, 0
	if !g.reliableLoss(g.sentN, g.lostN) {
		t.Fatal("genuine overload was ignored")
	}
	if g.rate < 31.9e6 || g.rate > 32.1e6 {
		t.Fatalf("expected a ~20%% cut to ~32 MB/s, got %.2f", g.rate/1e6)
	}
	if g.ceiling < g.rate || g.floor() != 8e6 {
		t.Fatalf("v2 should keep a ceiling above the rate and never drop the floor: ceiling %.2f floor %.2f", g.ceiling/1e6, g.floor()/1e6)
	}
}

// Loss-aware ceiling (v1.8.0): see cc.go. Measured 2026-10-10 on the real path: past ~45k pps a deep queue builds
// and the delay-only pacer ran 30-35 % of the wire as retransmissions.

type lossRun struct {
	goodput    float64 // payload bytes/s over the steady state
	retransFr  float64 // retransmitted share of packets sent in the steady state
	medQDelay  time.Duration
	rate, ceil float64
}

// runUpload pushes bulk data client -> server over `up` for total, measuring from steady on.
func runUpload(t *testing.T, up, down *simDir, maxMB float64, total, steady time.Duration) lossRun {
	key := []byte("test-key")
	cfg := Config{Key: key, SID: 0x1234567, MaxBps: maxMB * 1e6, Paths: 4}
	sc := cfg
	sc.Server = true
	cli, err := NewSession(cfg, &simIO{up, down, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewSession(sc, &simIO{down, up, make(chan struct{}), sync.Once{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })

	var got atomic.Int64
	go func() {
		st, err := srv.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := st.Read(buf)
			got.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		chunk := pattern(256<<10, 3)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := st.Write(chunk); err != nil {
				return
			}
		}
	}()
	time.Sleep(steady)
	g0, s0 := got.Load(), cli.Stats()
	up.mu.Lock()
	q0 := len(up.qd)
	up.mu.Unlock()
	time.Sleep(total - steady)
	g1, s1 := got.Load(), cli.Stats()
	close(stop)
	var r lossRun
	r.goodput = float64(g1-g0) / (total - steady).Seconds()
	if n := s1.PktsOut - s0.PktsOut; n > 0 {
		r.retransFr = float64(s1.Retrans-s0.Retrans) / float64(n)
	}
	up.mu.Lock()
	qd := append([]time.Duration(nil), up.qd[q0:]...)
	up.mu.Unlock()
	if len(qd) > 0 {
		sort.Slice(qd, func(i, j int) bool { return qd[i] < qd[j] })
		r.medQDelay = qd[len(qd)/2]
	}
	r.rate, r.ceil = s1.RateBps, s1.CeilingBps
	st.Reset()
	return r
}

// A hard rate cap with a deep drop-tail FIFO, 0.2 % random loss, 40 ms RTT, pace ceiling 80 MB/s.
func TestLossCeilingHardCap(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const capBps = 20e6
	// payload per 668 wire bytes (640 datagram + 28 IP/ICMP header) is the most a full link can carry
	ideal := capBps * float64(MaxPayload-overhead) / float64(MaxPayload+28)
	for _, aware := range []bool{false, true} { // false = the v1.7 delay-only pacer, for reference
		lossAwareOn.Store(aware)
		up := newSimDir(0.002, 20*time.Millisecond, capBps, 400*time.Millisecond, 11)
		up.recQ = true
		down := newSimDir(0.002, 20*time.Millisecond, 100e6, 400*time.Millisecond, 12)
		r := runUpload(t, up, down, 80, 16*time.Second, 6*time.Second)
		lossAwareOn.Store(false)
		t.Logf("loss-aware=%v cap %.0f MB/s (payload ideal %.1f): goodput %.1f MB/s (%.0f%% of ideal), retrans %.1f%%, median queue %v, rate %.1f ceiling %.1f MB/s",
			aware, capBps/1e6, ideal/1e6, r.goodput/1e6, 100*r.goodput/ideal, 100*r.retransFr, r.medQDelay, r.rate/1e6, r.ceil/1e6)
		if !aware {
			continue
		}
		if !raceBuild && r.goodput < 0.75*ideal {
			t.Errorf("goodput %.1f MB/s < 75%% of %.1f", r.goodput/1e6, ideal/1e6)
		}
		if r.retransFr >= 0.06 {
			t.Errorf("retransmitted fraction %.1f%% >= 6%%", 100*r.retransFr)
		}
		if r.medQDelay >= 40*time.Millisecond {
			t.Errorf("median queueing delay %v >= 40ms", r.medQDelay)
		}
	}
}

// Random loss on its own (2 %, nothing else) must not slow the sender: the threshold is relative to the baseline.
func TestLossCeilingRandomLossAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	run := func(aware bool) lossRun {
		lossAwareOn.Store(aware)
		defer lossAwareOn.Store(false)
		up := newSimDir(0.02, 20*time.Millisecond, 50e6, 400*time.Millisecond, 21)
		down := newSimDir(0.02, 20*time.Millisecond, 50e6, 400*time.Millisecond, 22)
		return runUpload(t, up, down, 12, 12*time.Second, 4*time.Second)
	}
	old := run(false)
	now := run(true)
	t.Logf("2%% loss, no cap: old goodput %.1f MB/s, new %.1f MB/s (rate %.1f, ceiling %.1f)", old.goodput/1e6, now.goodput/1e6, now.rate/1e6, now.ceil/1e6)
	if !raceBuild && now.goodput < 0.75*old.goodput {
		t.Errorf("loss-aware goodput %.1f < 75%% of the old %.1f MB/s", now.goodput/1e6, old.goodput/1e6)
	}
}

func TestLossStepUnit(t *testing.T) {
	lossAwareOn.Store(true)
	defer lossAwareOn.Store(false)
	c := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	// quiet 0.2 % loss: nothing happens
	c.sentN, c.lostN = 1000, 2
	if c.lossStep() || c.rate != 10e6 {
		t.Fatal("quiet interval changed the rate")
	}
	// fewer than 50 packets: ignored even at 100 % loss
	c.sentN, c.lostN = 40, 40
	if c.lossStep() || c.rate != 10e6 {
		t.Fatal("tiny interval was judged")
	}
	// 10 % loss: cut by 15 %, ceiling 5 % above the new rate
	c.sentN, c.lostN = 1000, 100
	if !c.lossStep() || c.rate < 8.49e6 || c.rate > 8.51e6 || c.ceiling < 8.9e6 || c.ceiling > 8.93e6 {
		t.Fatalf("rate %.3g ceiling %.3g", c.rate, c.ceiling)
	}
	// ceiling creeps up 2 % per quiet tick
	c0 := c.ceiling
	c.sentN, c.lostN = 1000, 1
	c.lossStep()
	if c.ceiling < c0*1.019 || c.ceiling > c0*1.021 {
		t.Fatalf("ceiling %.3g from %.3g", c.ceiling, c0)
	}
	// a learned high baseline moves the threshold: 2 % steady loss is not a cut
	b := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	for i := 0; i < 400; i++ {
		b.sentN, b.lostN = 1000, 20
		if b.lossStep() {
			t.Fatal("steady 2% loss cut the rate")
		}
	}
	if b.lossLimit() < 0.03 {
		t.Fatalf("limit %.3f", b.lossLimit())
	}
	// the remaining assertions pin the legacy v1 reliable rule (v2 has its own test below)
	relV2 = false
	defer func() { relV2 = os.Getenv("WAT_REL_V1") == "" }()
	// reliable carriers ignore a few late packets (a dead conn's tail) but cut on a burst of them, below minRate
	r := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	r.reliable, r.minRate = true, 8e6
	r.sentN, r.lostN = 1000, 3
	if r.lossStep() || r.rate != 10e6 {
		t.Fatal("reliable carrier reacted to a few late packets")
	}
	r.sentN, r.lostN = 1000, 20
	if r.lossStep() || r.rate != 10e6 {
		t.Fatal("reliable carrier reacted to 2 % late packets")
	}
	for i := 0; i < 5; i++ {
		r.sentN, r.lostN = 200, 30
		if !r.lossStep() {
			t.Fatal("reliable carrier ignored an overload")
		}
	}
	if r.rate > 3.3e6 || r.rate < 3.2e6 || r.floor() != 0.1e6 {
		t.Fatalf("reliable overload: rate %.2f MB/s floor %.2f", r.rate/1e6, r.floor()/1e6)
	}
	r.lowTicks = 1
	r.lossStep()
	if r.floor() != 8e6 {
		t.Fatal("start-rate floor not restored")
	}
	// loss that goes on at the floor is not ours: after ~2 s of it the loss rule stands down for a while
	f := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	f.reliable, f.minRate = true, 8e6
	cuts := 0
	for i := 0; i < 200; i++ {
		f.sentN, f.lostN = 10, 5
		if f.lossStep() {
			cuts++
		}
	}
	if f.lossOff == 0 || cuts > 30+relStuckTicks || f.floor() != 8e6 {
		t.Fatalf("floor-stuck loss: cuts %d lossOff %d floor %.2f", cuts, f.lossOff, f.floor()/1e6)
	}
}

// A shallow drop-tail buffer (6 ms at the link rate): the queue never grows enough for the delay rule to see it, the
// link just drops the excess. The delay-only pacer overshoots; the loss-aware ceiling should hold retransmissions down.
func TestLossCeilingShallowBuffer(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const capBps = 20e6
	ideal := capBps * float64(MaxPayload-overhead) / float64(MaxPayload+28)
	var fr [2]float64
	for i, aware := range []bool{false, true} {
		lossAwareOn.Store(aware)
		up := newSimDir(0.002, 20*time.Millisecond, capBps, 6*time.Millisecond, 31)
		up.recQ = true
		down := newSimDir(0.002, 20*time.Millisecond, 100e6, 400*time.Millisecond, 32)
		r := runUpload(t, up, down, 80, 16*time.Second, 6*time.Second)
		lossAwareOn.Store(false)
		fr[i] = r.retransFr
		t.Logf("loss-aware=%v shallow buffer: goodput %.1f MB/s (%.0f%% of ideal), retrans %.1f%%, median queue %v, rate %.1f ceiling %.1f MB/s",
			aware, r.goodput/1e6, 100*r.goodput/ideal, 100*r.retransFr, r.medQDelay, r.rate/1e6, r.ceil/1e6)
		if aware && r.retransFr >= 0.06 {
			t.Errorf("retransmitted fraction %.1f%% >= 6%%", 100*r.retransFr)
		}
		if aware && !raceBuild && r.goodput < 0.7*ideal {
			t.Errorf("goodput %.1f MB/s < 70%% of %.1f", r.goodput/1e6, ideal/1e6)
		}
	}
	if fr[1] > fr[0] {
		t.Errorf("loss-aware retransmits more (%.1f%%) than delay-only (%.1f%%)", 100*fr[1], 100*fr[0])
	}
}

// TestReliableBWPacer checks the delivery-rate pacer: an ack burst in one tick must not inflate the estimate (it is
// measured over >= 1 RTT), an app-limited lull must not lower it, and the window bounds inflight to a few BDP.
func TestReliableBWPacer(t *testing.T) {
	if !relV2 {
		t.Skip("v1 forced")
	}
	c := newCC(1e6, 2e5, 80e6, 0)
	c.reliable = true
	now := time.Now()
	for i := 0; i < 10; i++ {
		c.sample(50*time.Millisecond, now) // minRTT = 50 ms
	}
	// steady 20 MB/s for 2 s, delivered in 10 ms chunks (bursty within a tick), ticks every 50 ms
	for k := 1; k <= 40; k++ {
		at := now.Add(time.Duration(k) * 50 * time.Millisecond)
		c.onDelivered(int(20e6 * 0.05))
		c.sample(50*time.Millisecond, at)
		c.limited, c.cwndLim = true, true
		c.tick(at)
	}
	if c.maxBW < 18e6 || c.maxBW > 24e6 {
		t.Fatalf("bw estimate off: %.1f MB/s (want ~20)", c.maxBW/1e6)
	}
	// cwnd bounded to a few BDP (BDP = 20 MB/s * 50 ms = 1 MB)
	if cw := c.cwnd(); cw > 4<<20 {
		t.Fatalf("cwnd not BDP-bounded: %d", cw)
	}
	// an app-limited lull (no delivery) must not lower the estimate
	hi := c.maxBW
	for k := 41; k <= 50; k++ {
		at := now.Add(time.Duration(k) * 50 * time.Millisecond)
		c.sample(50*time.Millisecond, at)
		c.limited = false
		c.tick(at)
	}
	if c.maxBW < hi*0.9 {
		t.Fatalf("app-limited lull lowered the estimate: %.1f -> %.1f", hi/1e6, c.maxBW/1e6)
	}
}
