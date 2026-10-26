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
	// genuine loss (nothing spurious): a direct carrier does not cut since 2.4.18, TCP below does the congestion
	// control; a CDN carrier still cuts (below)
	d := newCC(40e6, 0.1e6, 80e6, 8*time.Millisecond)
	d.reliable, d.direct, d.minRate, d.hardMin = true, true, 8e6, 8e6
	if relLossCuts {
		t.Skip("WAT_REL_LOSSCUT set")
	}
	if d.reliableLoss(200, 30) || d.rate != 40e6 {
		t.Fatalf("loss cut a reliable carrier by default: rate %.2f", d.rate/1e6)
	}
	// a CDN carrier: a gentle multiplicative cut, floored at hardMin, with a ceiling above it
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

// TestReliableProbeRTT checks that a persistently queued reliable carrier re-measures its base RTT by draining.
// The queue is modelled physically: inflight tracks cwnd (so during a drain it falls to the floor), and the RTT a
// sample reads is the base plus the queueing delay of the current inflight. A shallow drain (the 2.4.12 bug) would
// leave inflight — and so the sampled RTT — high, and minRTT would climb with the self-inflicted queue.
func TestReliableProbeRTT(t *testing.T) {
	if !relV2 {
		t.Skip("v1 forced")
	}
	const base = 100 * time.Millisecond
	const rate = 10e6 // bytes/s capacity; queue delay = inflight/rate
	c := newCC(5e6, 2e5, 80e6, 0)
	c.reliable, c.maxPlain = true, 1400
	now := time.Now()
	c.sample(base, now)
	inflight := 3_000_000 // ~3 MB standing queue (300 ms of bufferbloat on top of the 100 ms base)
	drainedOnce := false
	for k := 1; k <= 300; k++ {
		at := now.Add(time.Duration(k) * 50 * time.Millisecond)
		c.inflight = inflight
		cw := c.cwnd()
		// inflight relaxes toward the window: a drain (cwnd -> a few packets) empties it within a couple of ticks,
		// and otherwise the overfilling pacer keeps it pinned near the cap.
		if inflight > cw {
			inflight -= 1_600_000 // drains fast once cwnd drops
			if inflight < cw {
				inflight = cw
			}
		} else {
			inflight += 200_000
			if inflight > cw {
				inflight = cw
			}
		}
		if c.draining && inflight <= c.drainFloor() {
			drainedOnce = true
		}
		rtt := base + time.Duration(float64(inflight)/rate*float64(time.Second))
		c.inflight = inflight
		c.onDelivered(int(rate * 0.05))
		c.sample(rtt, at)
		c.limited, c.cwndLim = true, true
		c.tick(at)
	}
	if !drainedOnce {
		t.Fatal("the drain never emptied the queue to the floor in 15 s")
	}
	if c.minRTT > 150*time.Millisecond {
		t.Fatalf("minRTT climbed with the queue to %v (base was 100 ms); the BDP window would run away", c.minRTT)
	}
}

// TestReliableProbeNoAppLimitedPollution pins the 2.4.15 fix: an app-limited reliable sender (little in flight, e.g.
// the receive side of a transfer) must never raise minRTT from a high sample. Such a sender builds no queue of its
// own, so a delayed sample is reverse-path or scheduling noise, not a base to re-measure from. Draining there once
// polluted minRTT (field 2026-10-13: a client receiving a download saw minRTT jump 107 -> 545 ms and its next upload
// collapsed). minRTT may still only fall.
func TestReliableProbeNoAppLimitedPollution(t *testing.T) {
	if !relV2 {
		t.Skip("v1 forced")
	}
	c := newCC(5e6, 2e5, 80e6, 0)
	c.reliable, c.maxPlain = true, 1400
	now := time.Now()
	c.sample(107*time.Millisecond, now) // true base
	for k := 1; k <= 400; k++ {         // 20 s, well past the 10 s stale window
		at := now.Add(time.Duration(k) * 50 * time.Millisecond)
		c.inflight = 3000 // below the drain floor: nothing of ours is queued
		c.sample(545*time.Millisecond, at)
		c.limited, c.cwndLim, c.tokLim = false, false, false // app-limited
		c.tick(at)
	}
	if c.draining {
		t.Fatal("entered a drain while app-limited: there was no queue to clear")
	}
	if c.minRTT > 150*time.Millisecond {
		t.Fatalf("an app-limited sample raised minRTT to %v (base 107 ms)", c.minRTT)
	}
}

// A direct reliable carrier (Config.Direct, 2.4.18) lets TCP pace: its window covers about a second of delivery, not
// a few minRTT, it keeps the normal loss timer (a longer one measured slower), and it never drains to re-measure minRTT.
func TestDirectWindowAndLossTimer(t *testing.T) {
	mk := func(direct bool) cc {
		c := newCC(10e6, 0.1e6, 1250e6, 8*time.Millisecond)
		c.reliable, c.direct = true, direct
		c.maxBW, c.minRTT, c.srtt, c.maxPlain = 50e6, 40*time.Millisecond, 60*time.Millisecond, 4096
		return c
	}
	cdn, dir := mk(false), mk(true)
	if w := dir.cwnd(); w < int(50e6*relDirectWin.Seconds()) {
		t.Fatalf("direct window %d < %v of delivery", w, relDirectWin)
	}
	if dir.cwnd() <= cdn.cwnd() {
		t.Fatalf("windows: direct %d, cdn %d", dir.cwnd(), cdn.cwnd())
	}
	if relDirectLossTime == 0 && (dir.lossTime() != cdn.lossTime() || dir.pto() != cdn.pto()) {
		t.Fatalf("direct timers changed without WAT_DIRECT_LOSS_MS: %v/%v vs %v/%v", dir.lossTime(), dir.pto(), cdn.lossTime(), cdn.pto())
	}
	dir.inflight = 1 << 24
	dir.srtt = 200 * time.Millisecond
	dir.probeAt = time.Now().Add(-time.Second)
	dir.probeRTT(time.Now())
	if dir.draining {
		t.Fatal("a direct carrier entered the minRTT drain")
	}
}

// A pool connection that stalls leaves a hole per packet it carries, far more than one ACK frame's 64 ranges. Its
// packets arriving late must still be acked once, by a late-ACK frame, and a sender must neither take an RTT sample
// from that frame nor declare anything lost by it.
func TestLateAck(t *testing.T) {
	rcv := profSession(t, poolProfile, Config{})
	rcv.mu.Lock()
	recv := func(pn uint64) { // the bookkeeping of the receive path
		rcv.rxRanges.add(pn, pn+1)
		rcv.rxRanges.trim(rcv.rxKeep)
		rcv.rxSince = append(rcv.rxSince, pn)
	}
	reported := rangeSet{}
	ack := func() {
		p := rcv.appendLateAck(nil, time.Now())
		p = appendAck(p, rcv.rxRanges, 0, rcv.ackMax)
		r := &reader{b: p}
		for len(r.b) > 0 {
			if r.byte() != frAck {
				t.Fatal("not an ACK frame")
			}
			_, _, rs := parseAck(r)
			if r.err != nil {
				t.Fatal(r.err)
			}
			for _, x := range rs {
				reported.add(x.lo, x.hi)
			}
		}
	}
	for pn := uint64(0); pn < 4000; pn += 2 { // the odd packets ride a stalled connection
		recv(pn)
		if pn%12 == 0 {
			ack()
		}
	}
	for pn := uint64(1); pn < 4000; pn += 2 {
		recv(pn)
		if pn%11 == 0 {
			ack()
		}
	}
	for i := 0; i < 100 && len(rcv.rxLate)+len(rcv.rxSince) > 0; i++ {
		ack()
	}
	rcv.mu.Unlock()
	for pn := uint64(1); pn < 4000; pn += 2 {
		if !reported.contains(pn) {
			t.Fatalf("late packet %d never acked (late acks %d)", pn, rcv.stats.AckLate)
		}
	}
	if rcv.stats.AckLate == 0 {
		t.Fatal("AckLate not counted")
	}

	snd := profSession(t, poolProfile, Config{})
	snd.mu.Lock()
	defer snd.mu.Unlock()
	now := time.Now()
	for pn := uint64(0); pn < 10; pn++ {
		sp := snd.newSent()
		sp.pn, sp.at, sp.size = pn, now.Add(-10*time.Second), 1000
		snd.sent = append(snd.sent, sp)
		snd.inflight += sp.size
	}
	srtt := snd.cc.srtt
	snd.onAck(5, lateAckDelay*time.Microsecond, rangeSet{{5, 6}}, now)
	if !snd.sent[5].done || snd.sent[5].lost {
		t.Fatal("late ACK did not deliver packet 5")
	}
	for i, sp := range snd.sent {
		if i != 5 && sp.done {
			t.Fatalf("late ACK declared packet %d lost", i)
		}
	}
	if snd.cc.srtt != srtt {
		t.Fatalf("late ACK took an RTT sample: srtt %v -> %v", srtt, snd.cc.srtt)
	}
}

// A direct carrier paces at relStartGain until its estimate stops growing while busy; idle time does not end startup.
func TestDirectStartup(t *testing.T) {
	c := newCC(8e6, 0.1e6, 1250e6, 8*time.Millisecond)
	c.reliable, c.direct = true, true
	c.maxBW, c.minRTT, c.srtt, c.maxPlain = 10e6, 40*time.Millisecond, 200*time.Millisecond, 4096
	now := time.Now()
	c.bwAt, c.delLast = now, 0
	c.tickReliable(now, false, false)
	for i := 1; i <= 40; i++ { // two seconds idle
		c.tickReliable(now.Add(time.Duration(i)*50*time.Millisecond), false, false)
	}
	if c.grown || c.rate < relStartGain*10e6*0.99 {
		t.Fatalf("idle ended startup: grown %v rate %.1f MB/s", c.grown, c.rate/1e6)
	}
	busyFrom := now.Add(2 * time.Second)
	for i := 0; i < 20; i++ { // busy, estimate flat at 10 MB/s for a second (> 3 srtt)
		c.delivered += 500e3
		c.tickReliable(busyFrom.Add(time.Duration(i)*50*time.Millisecond), false, true)
	}
	if !c.grown || c.rate > relBWGain*c.maxBW*1.01 {
		t.Fatalf("flat busy estimate kept startup: grown %v rate %.1f MB/s maxBW %.1f", c.grown, c.rate/1e6, c.maxBW/1e6)
	}
}

// TestReliableHoldsOnDeadPath: once a delivery rate was measured, a window of busy ticks that deliver nothing (a dead
// path) holds the rate; before 3.0.1 the estimate fell back to "none yet" and the slow-start ramp ran to the maximum.
func TestReliableHoldsOnDeadPath(t *testing.T) {
	c := newCC(10e6, 0.1e6, 80e6, 8*time.Millisecond)
	c.reliable = true
	now := time.Now()
	c.tickReliable(now, false, true)
	for i := 0; i < 5; i++ { // 20 MB/s delivered
		now = now.Add(100 * time.Millisecond)
		c.onDelivered(2_000_000)
		c.tickReliable(now, false, true)
	}
	if !c.bwSeen || c.maxBW <= 0 {
		t.Fatalf("no estimate after delivery: seen %v maxBW %.1f", c.bwSeen, c.maxBW/1e6)
	}
	dead := func() { // nothing delivered, sender busy and rate-limited
		now = now.Add(100 * time.Millisecond)
		c.limited = true
		c.tickReliable(now, false, true)
	}
	for i := 0; c.maxBW > 0; i++ {
		if i > 10*bwWin {
			t.Fatal("estimate never fell to zero")
		}
		dead()
	}
	r := c.rate
	if r >= c.maxRate {
		t.Fatalf("rate already at the maximum (%.1f MB/s): the test would prove nothing", r/1e6)
	}
	for i := 0; i < 50; i++ {
		dead()
	}
	if c.rate != r {
		t.Fatalf("rate moved on a dead path: %.1f -> %.1f MB/s", r/1e6, c.rate/1e6)
	}
}
