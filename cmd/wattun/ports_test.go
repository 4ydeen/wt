package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// tcpRig: a wattun client+server pair over the udp carrier on loopback, one echo service, one public port.
type tcpRig struct {
	pub, target int
	cs, ss      *portStat
}

func newTCPRig(t *testing.T) *tcpRig {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go acceptLoop(echo, func(c net.Conn) { io.Copy(c, c); c.Close() })
	target := echo.Addr().(*net.TCPAddr).Port

	key := []byte("ports-test-key")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key}, us)
	t.Cleanup(srv.Close)
	al := newAllow("", "")
	al.setPorts([]int{target})
	go func() {
		for s := range srv.New {
			go serve(s, 1, 65535, al)
		}
	}()
	uc, err := wat.NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := wat.NewSession(wat.Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	waitFor(t, "session alive", 5*time.Second, sess.Alive)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pub := ln.Addr().(*net.TCPAddr).Port
	cs := portReg.get("c", pub)
	tun := newTunnel([]*wat.Session{sess})
	go acceptLoop(ln, func(c net.Conn) { forward(tun, c, target, cs) })
	return &tcpRig{pub: pub, target: target, cs: cs, ss: portReg.get("s", target)}
}

// echoN sends n bytes through the public port and reads them back; returns bytes read and the elapsed time.
func (r *tcpRig) echoN(t *testing.T, n int) (int, time.Duration) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t0 := time.Now()
	go func() {
		buf := make([]byte, 16<<10)
		for sent := 0; sent < n; {
			k := min(len(buf), n-sent)
			if _, err := c.Write(buf[:k]); err != nil {
				return
			}
			sent += k
		}
	}()
	got, _ := io.CopyN(io.Discard, c, int64(n))
	return int(got), time.Since(t0)
}

func within(got, want int64, pct float64) bool {
	d := float64(got - want)
	if d < 0 {
		d = -d
	}
	return d <= float64(want)*pct/100
}

func TestPortCountersAndShape(t *testing.T) {
	r := newTCPRig(t)
	const n = 1 << 20
	hold, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "active conn", 3*time.Second, func() bool { return r.cs.connsActive.Load() == 1 && r.ss.connsActive.Load() == 1 })
	got, _ := r.echoN(t, n)
	if got != n {
		t.Fatalf("echoed %d of %d", got, n)
	}
	hold.Close()
	waitFor(t, "conns drained", 3*time.Second, func() bool { return r.cs.connsActive.Load() == 0 && r.ss.connsActive.Load() == 0 })
	for name, p := range map[string]*portStat{"client": r.cs, "server": r.ss} {
		if !within(p.bytesUp.Load(), n, 1) || !within(p.bytesDown.Load(), n, 1) {
			t.Errorf("%s: up=%d down=%d, want ~%d", name, p.bytesUp.Load(), p.bytesDown.Load(), n)
		}
		if p.connsTotal.Load() != 2 {
			t.Errorf("%s conns_total=%d, want 2", name, p.connsTotal.Load())
		}
	}
	portReg.tick()
	snap := portReg.snapshot("c")
	b, _ := json.Marshal(snap)
	var back map[string]map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	e := back[strconv.Itoa(r.pub)]
	for _, k := range []string{"bytes_up", "bytes_down", "conns_total", "conns_active", "udp_flows_active", "dgram_up", "dgram_down",
		"errors", "refused", "rate_bps_up", "rate_bps_down", "peak_bps_up", "peak_bps_down", "rate_limit_bps", "quota_limit", "quota_used", "quota_exceeded"} {
		if _, ok := e[k]; !ok {
			t.Errorf("/ports entry lacks %q", k)
		}
	}
	if e["peak_bps_up"].(float64) <= 0 {
		t.Errorf("peak not recorded: %v", e["peak_bps_up"])
	}
}

func TestPortRateLimit(t *testing.T) {
	r := newTCPRig(t)
	portReg.applyLimits([]limitSpec{{Port: r.pub, Rate: 1_000_000}})
	t.Cleanup(func() { portReg.applyLimits(nil) })
	const n = 2_000_000
	got, el := r.echoN(t, n)
	if got != n {
		t.Fatalf("echoed %d of %d", got, n)
	}
	mbs := float64(n) / el.Seconds() / 1e6
	t.Logf("%.2f MB/s", mbs)
	if mbs < 0.8 || mbs > 1.2 {
		t.Fatalf("rate %.2f MB/s, want 0.8-1.2", mbs)
	}
}

func TestPortQuotaCutoff(t *testing.T) {
	r := newTCPRig(t)
	portReg.applyLimits([]limitSpec{{Port: r.pub, Quota: 400_000}})
	t.Cleanup(func() { portReg.applyLimits(nil); portReg.resetQuota(r.pub) })
	got, _ := r.echoN(t, 3_000_000)
	if got >= 3_000_000 {
		t.Fatalf("transfer was not cut off (%d bytes)", got)
	}
	waitFor(t, "quota exceeded", 3*time.Second, func() bool { return r.cs.exceeded() })
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.pub)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("new connection was served")
	}
	if r.cs.refused.Load() == 0 {
		t.Error("refused counter not incremented")
	}
	// reset (loopback only) lets traffic through again
	req := httptest.NewRequest("POST", "/quota/reset?port="+strconv.Itoa(r.pub), nil)
	req.RemoteAddr = "8.8.8.8:1234"
	w := httptest.NewRecorder()
	quotaResetHandler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-loopback reset got %d", w.Code)
	}
	req.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	quotaResetHandler(w, req)
	if w.Code != 200 || r.cs.exceeded() {
		t.Errorf("loopback reset: code %d exceeded=%v", w.Code, r.cs.exceeded())
	}
}

func TestQuotaPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wat.yml.quota.json")
	r1 := newRegistry()
	r1.loadQuota(path)
	r1.applyLimits([]limitSpec{{Port: 4242, Quota: 1000}})
	r1.get("c", 4242).add(true, 300)
	r1.get("c", 4242).add(false, 200)
	r1.save()
	r2 := newRegistry() // "restart"
	r2.loadQuota(path)
	r2.applyLimits([]limitSpec{{Port: 4242, Quota: 1000}})
	if u := r2.get("c", 4242).qused.Load(); u != 500 {
		t.Fatalf("restored usage %d, want 500", u)
	}
	r2.get("c", 4242).add(true, 600)
	if !r2.get("c", 4242).exceeded() {
		t.Fatal("quota should be exceeded after restore + 600")
	}
	if !r2.resetQuota(4242) || r2.get("c", 4242).exceeded() {
		t.Fatal("reset failed")
	}
	r3 := newRegistry()
	r3.loadQuota(path)
	if u := r3.get("c", 4242).qused.Load(); u != 0 {
		t.Fatalf("reset not persisted: %d", u)
	}
}

func TestLimitsConfigAndHotReload(t *testing.T) {
	c, err := parseConfig("mode: client\nports:\n  - 7001\nlimits:\n  - 7001 rate=5MB quota=100GB\n  - 7002 rate=300k\n", knownKeys)
	if err != nil || len(c.Limits) != 2 || c.Limits[0] != (limitSpec{7001, 5_000_000, 100_000_000_000}) || c.Limits[1].Rate != 300_000 {
		t.Fatalf("parse: %+v %v", c, err)
	}
	for _, bad := range []string{"limits:\n  - 7001 rate=abc\n", "limits:\n  - 7001 speed=1\n", "limits:\n  - x\n"} {
		if _, err := parseConfig(bad, knownKeys); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "wat.yml")
	writeCfg(t, path, "mode: client\nlimits:\n  - 7003 rate=1MB\n", 1)
	r := newRegistry()
	c, _ = parseConfig(mustRead(t, path), knownKeys)
	r.applyLimits(c.Limits)
	st := r.get("c", 7003)
	w := &cfgWatcher{path: path, known: knownKeys, interval: 20 * time.Millisecond, onPorts: func(*fileConfig) {},
		onLimits: func(c *fileConfig) { r.applyLimits(c.Limits) }}
	w.start(c)
	go w.run()
	if st.rateLim.Load() != 1_000_000 || st.bUp.Load() == nil {
		t.Fatal("initial limit not applied")
	}
	writeCfg(t, path, "mode: client\nlimits:\n  - 7003 rate=2MB quota=1GB\n", 2)
	waitFor(t, "limit reload", 3*time.Second, func() bool { return st.rateLim.Load() == 2_000_000 && st.quota.Load() == 1_000_000_000 })
	writeCfg(t, path, "mode: client\nlimits:\n", 3)
	waitFor(t, "limit removal", 3*time.Second, func() bool { return st.rateLim.Load() == 0 && st.bUp.Load() == nil && st.quota.Load() == 0 })
}

// Lifetime totals survive a restart: a new registry loads what the old one saved and reports base + new traffic.
func TestTotalsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.totals.json")
	a := newRegistry()
	a.loadTotals(path, func() (uint64, uint64) { return 1000, 2000 })
	p := a.get("c", 20001)
	p.add(true, 300)
	p.add(false, 700)
	p.connsTotal.Add(2)
	a.save()

	b := newRegistry()
	b.loadTotals(path, func() (uint64, uint64) { return 10, 20 })
	q := b.get("c", 20001)
	q.add(true, 5)
	m := b.snapshot("c")["20001"].(map[string]any)
	if m["bytes_up_total"] != int64(305) || m["bytes_down_total"] != int64(700) || m["conns_all_time"] != int64(2) {
		t.Fatalf("totals after restart: %v", m)
	}
	if m["bytes_up"] != int64(5) {
		t.Fatalf("live counter should start at zero: %v", m["bytes_up"])
	}
	if in, out := b.sessionTotals(10, 20); in != 1010 || out != 2020 {
		t.Fatalf("session totals %d/%d", in, out)
	}
}
