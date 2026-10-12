package wat

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// ICMP never implements Profiled, so it always runs the original code path. The sim tests (sim_test.go, unchanged)
// pin the behaviour of that path; this pins that the carrier cannot opt in by accident.
func TestICMPHasNoProfile(t *testing.T) {
	if _, ok := any(&ICMPIO{}).(Profiled); ok {
		t.Fatal("ICMPIO implements Profiled: ICMP behaviour would change")
	}
	if p := profileOf(&simIO{}); p != (Profile{}) {
		t.Fatalf("carrier without a profile got %+v", p)
	}
}

type profIO struct {
	simIO
	p Profile
}

func (p *profIO) Profile() Profile { return p.p }

func profSession(t *testing.T, p Profile, cfg Config) *Session {
	t.Helper()
	d := newSimDir(0, time.Millisecond, 1e6, time.Second, 1)
	cfg.Key = []byte("k")
	s, err := NewSession(cfg, &profIO{simIO{d, d, make(chan struct{}), sync.Once{}}, p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Without a profile every default is the original one; with one, only the carrier's own values change.
func TestProfileDefaults(t *testing.T) {
	plain := profSession(t, Profile{}, Config{})
	if plain.maxPlain != MaxPayload-overhead || plain.cc.reliable || plain.replayWin != 1024 || plain.ackMax != 20 ||
		plain.rxKeep != 64 || plain.cc.rate != 1.5e6 {
		t.Fatalf("zero profile changed defaults: maxPlain=%d reliable=%v replay=%d ack=%d keep=%d rate=%v",
			plain.maxPlain, plain.cc.reliable, plain.replayWin, plain.ackMax, plain.rxKeep, plain.cc.rate)
	}
	// the zero profile still clamps an oversized -mtu to 1400
	if s := profSession(t, Profile{}, Config{MaxPayload: 16000}); s.maxPlain != MaxPayloadHi-overhead {
		t.Fatalf("zero profile allowed mtu %d", s.maxPlain+overhead)
	}
	pool := profSession(t, poolProfile, Config{})
	if pool.maxPlain != 4096-overhead || !pool.cc.reliable || pool.replayWin != reliableReplayWin || pool.ackMax != 64 || pool.cc.rate != 8e6 {
		t.Fatalf("pool profile not applied: maxPlain=%d reliable=%v replay=%d ack=%d rate=%v",
			pool.maxPlain, pool.cc.reliable, pool.replayWin, pool.ackMax, pool.cc.rate)
	}
	if s := profSession(t, poolProfile, Config{MaxPayload: 1 << 20}); s.maxPlain != poolMaxMTU-overhead {
		t.Fatalf("pool mtu not clamped to %d: %d", poolMaxMTU, s.maxPlain+overhead)
	}
	if s := profSession(t, poolProfile, Config{MaxPayload: 900, InitBps: 3e6}); s.maxPlain != 900-overhead || s.cc.rate != 3e6 {
		t.Fatalf("explicit config must beat the profile: maxPlain=%d rate=%v", s.maxPlain, s.cc.rate)
	}
	if s := profSession(t, udpProfile, Config{}); s.maxPlain != 1400-overhead || s.cc.reliable {
		t.Fatalf("udp profile: maxPlain=%d reliable=%v", s.maxPlain, s.cc.reliable)
	}
}

// The unreliable pacer keeps judging the mean delay. The reliable pacer (2.4.11) ignores delay entirely and tracks
// the measured delivery rate instead: RTT jitter must not move it, and its rate settles near the delivery rate it is
// actually achieving, never running away above it.
func TestReliableCCJudgesFloor(t *testing.T) {
	// unreliable: a standing queue (every sample at 70 ms over a 40 ms base) still backs the pacer off
	u := newCC(5e6, 2e5, 16e6, 8*time.Millisecond)
	now := time.Now()
	for i := 0; i < 20; i++ {
		u.sample(40*time.Millisecond, now)
	}
	u.tick(now.Add(time.Second))
	start := u.rate
	for k := 1; k <= 10; k++ {
		at := now.Add(time.Second + time.Duration(k)*60*time.Millisecond)
		for i := 0; i < 100; i++ {
			u.sample(70*time.Millisecond, at)
		}
		u.limited = true
		u.tick(at)
	}
	if u.rate/start > 1 {
		t.Fatalf("unreliable pacer should react to a standing queue: rate x%.2f", u.rate/start)
	}

	// reliable: deliver a steady 10 MB/s while RTT jitters between 40 and 160 ms. The pacer must not cut on the
	// jitter, and must settle near the delivery rate (relBWGain above it), not run away to the max.
	c := newCC(5e6, 2e5, 80e6, 8*time.Millisecond)
	c.reliable = true
	base := time.Now()
	for i := 0; i < 20; i++ {
		c.sample(40*time.Millisecond, base)
	}
	const bwPerTick = 10e6 * 0.06 // 10 MB/s over 60 ms ticks
	for k := 1; k <= 60; k++ {
		at := base.Add(time.Duration(k) * 60 * time.Millisecond)
		c.sample(40*time.Millisecond, at)
		if k%3 == 0 {
			c.sample(160*time.Millisecond, at) // a stalled connection's late sample
		}
		c.onDelivered(int(bwPerTick))
		c.limited = true
		c.cwndLim = true
		c.tick(at)
	}
	if c.diag.DelayCuts != 0 || c.diag.DeepTrips != 0 {
		t.Fatalf("reliable pacer cut on RTT jitter: %d delay cuts, %d deep trips", c.diag.DelayCuts, c.diag.DeepTrips)
	}
	if c.rate < 9e6 || c.rate > 10e6*relBWGain*1.2 {
		t.Fatalf("reliable rate should settle near the 10 MB/s delivery rate, got %.2f MB/s", c.rate/1e6)
	}
}

func TestReliableLossTimersRelaxed(t *testing.T) {
	a, b := newCC(1e6, 1e5, 1e6, 0), newCC(1e6, 1e5, 1e6, 0)
	b.reliable = true
	for _, c := range []*cc{&a, &b} {
		c.sample(40*time.Millisecond, time.Now())
	}
	if a.pto() >= reliablePTO || a.lossTime() >= reliableLossTime {
		t.Fatalf("unreliable timers changed: pto=%v loss=%v", a.pto(), a.lossTime())
	}
	if b.pto() < reliablePTO || b.lossTime() < reliableLossTime {
		t.Fatalf("reliable timers not relaxed: pto=%v loss=%v", b.pto(), b.lossTime())
	}
}

// ---- end to end over a real loopback pool

// directPool is a Server and a client Session on a real loopback pool, with no wrapper hiding the carrier's Profile.
func directPool(t *testing.T, proxy func(addr string) string, cfg Config) (cli *Session, pc *TCPPoolClient, ps *TCPPoolServer, srv *Server) {
	t.Helper()
	var err error
	if ps, err = NewTCPPoolServer("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	cfg.Key = []byte("profile-key")
	srv = NewServer(cfg, ps)
	srv.IdleTimeout = 5 * time.Second
	emuServe(srv)
	addr := ps.Addr().String()
	if proxy != nil {
		addr = proxy(addr)
	}
	if pc, err = NewTCPPoolClient(addr, 8); err != nil {
		t.Fatal(err)
	}
	if cli, err = NewSession(cfg, pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	return
}

func getPattern(t *testing.T, cli *Session, n int) {
	t.Helper()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	var h [5]byte
	binary.BigEndian.PutUint32(h[1:], uint32(n))
	go func() { st.Write(h[:]); st.CloseWrite() }()
	got, err := readAll(st)
	if err != nil || len(got) != n {
		t.Fatalf("download: err=%v got %d want %d", err, len(got), n)
	}
}

func TestPoolDefaultsOverLoopback(t *testing.T) {
	cli, pc, _, srv := directPool(t, nil, Config{})
	if want := 4096 - overhead; cli.maxPlain != want {
		t.Fatalf("pool client maxPlain %d, want %d", cli.maxPlain, want)
	}
	getPattern(t, cli, 8<<20)
	if st := srv.Stats(); st.PktsOut > 8<<20/3000 {
		t.Fatalf("8 MB took %d packets: datagrams are not using the large default", st.PktsOut)
	}
	if pc.Conns() != 8 {
		t.Fatalf("%d conns", pc.Conns())
	}
}

// A pool reorders by whole stalls of a TCP connection. Packet-count loss detection, a 1024-packet replay window and
// 20 SACK ranges turned that into 56 % spurious retransmits on the bench link; at 640 B datagrams (the most reordering
// per stall) a reliable session must now repair almost nothing and still deliver every byte.
func TestPoolReorderNoSpuriousRetrans(t *testing.T) {
	up, down := newEmuWire(1), newEmuWire(2)
	cli, _, _, srv := directPool(t, func(a string) string { return emuProxy(t, a, up, down) }, Config{MaxPayload: 640})
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	getPattern(t, cli, 12<<20)
	el := time.Since(t0)
	st := srv.Stats()
	t.Logf("12 MB in %v (%.1f MB/s), %d packets, %d retrans, wire stalls %d", el.Round(time.Millisecond), 12/el.Seconds(), st.PktsOut, st.Retrans, down.stalled)
	if down.stalled < 5 {
		t.Fatalf("the emulated link produced only %d stalls: the test proves nothing", down.stalled)
	}
	if st.Retrans*50 > st.PktsOut { // 2 %; was 56 %
		t.Fatalf("%d of %d packets were retransmitted", st.Retrans, st.PktsOut)
	}
}

// Killing connections destroys their queued datagrams. Under the relaxed (reliable) timers the session must still
// notice after the longer PTO and finish the transfer intact.
func TestReliableRepairsKilledConns(t *testing.T) {
	cli, pc, ps, _ := directPool(t, nil, Config{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for _, d := range []time.Duration{100, 350} {
			select {
			case <-time.After(d * time.Millisecond):
				ps.kill(4)
			case <-stop:
				return
			}
		}
	}()
	t0 := time.Now()
	getPattern(t, cli, 24<<20)
	t.Logf("24 MB with 8 connection kills in %v", time.Since(t0).Round(time.Millisecond))
	deadline := time.Now().Add(5 * time.Second)
	for pc.Conns() < 8 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if pc.Conns() < 8 {
		t.Fatalf("pool did not recover: %d conns", pc.Conns())
	}
}

func TestUDPProfileOverLoopback(t *testing.T) {
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Key: []byte("u")}, us)
	emuServe(srv)
	uc, err := NewUDPClient(us.Addr().(*net.UDPAddr).String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: []byte("u")}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	if cli.maxPlain != 1400-overhead {
		t.Fatalf("udp client maxPlain %d", cli.maxPlain)
	}
	getPattern(t, cli, 4<<20)
}
