package wat

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"runtime"
	"sync"
	"testing"
	"time"
)

// poolRig is a real Server on a loopback tcp/tls pool listener (same stream protocol as udpRig).
type poolRig struct {
	srv  *Server
	ps   *TCPPoolServer
	addr string
	tap  *sizeTap
	key  []byte
	mtu  int
	tls  bool
}

func newPoolRig(t *testing.T, mtu int, useTLS bool) *poolRig {
	t.Helper()
	var ps *TCPPoolServer
	var err error
	if useTLS {
		ps, err = NewTLSPoolServer("127.0.0.1:0", "", "")
	} else {
		ps, err = NewTCPPoolServer("127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := &poolRig{ps: ps, addr: ps.Addr().String(), tap: &sizeTap{}, key: []byte("pool-key"), mtu: mtu, tls: useTLS}
	srv := NewServer(Config{Key: r.key, MaxPayload: mtu}, tapServer{ps, r.tap})
	srv.IdleTimeout = 5 * time.Second
	r.srv = srv
	go func() {
		for s := range srv.New {
			go func(s *Session) {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go serveUDPStream(st)
				}
			}(s)
		}
	}()
	t.Cleanup(srv.Close)
	return r
}

func (r *poolRig) pio(t *testing.T) *TCPPoolClient {
	t.Helper()
	var c *TCPPoolClient
	var err error
	if r.tls {
		c, err = NewTLSPoolClient(r.addr, 8, TLSClientOptions{ServerName: "example.com"})
	} else {
		c, err = NewTCPPoolClient(r.addr, 8)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *poolRig) client(t *testing.T, key []byte) *Session {
	t.Helper()
	s, err := NewSession(Config{Key: key, MaxPayload: r.mtu}, tapClient{r.pio(t), r.tap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// kill closes n connections of the server's busiest pool from the server side.
func (s *TCPPoolServer) kill(n int) {
	s.mu.Lock()
	var victims []*poolConn
	for _, set := range s.pools {
		for pc := range set {
			if len(victims) < n {
				victims = append(victims, pc)
			}
		}
	}
	s.mu.Unlock()
	for _, pc := range victims {
		pc.fail()
	}
}

func poolBulk(t *testing.T, r *poolRig, cli *Session, n int) {
	t.Helper()
	t0 := time.Now()
	up := pattern(n, 3)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	go func() { st.Write(append([]byte{'U'}, up...)); st.CloseWrite() }()
	sum, err := readAll(st)
	want := sha256.Sum256(up)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("upload digest mismatch: err=%v len=%d", err, len(sum))
	}
	tUp := time.Since(t0)
	t0 = time.Now()
	st, err = cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{'D', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(req[1:], uint32(n))
	go func() { st.Write(req); st.CloseWrite() }()
	got, err := readAll(st)
	if err != nil || !bytes.Equal(got, pattern(n, 7)) {
		t.Fatalf("download mismatch: err=%v got %d want %d", err, len(got), n)
	}
	t.Logf("mtu %d: up %v down %v, max datagram %d", r.mtu, tUp, time.Since(t0), r.tap.max.Load())
}

func poolBulkTest(t *testing.T, mtu int, useTLS bool) {
	r := newPoolRig(t, mtu, useTLS)
	poolBulk(t, r, r.client(t, r.key), 4<<20)
}

func TestTCPBulk(t *testing.T) { poolBulkTest(t, 0, false) }
func TestTLSBulk(t *testing.T) { poolBulkTest(t, 0, true) }

func TestTCPLargeDatagrams(t *testing.T) {
	r := newPoolRig(t, 1400, false)
	poolBulk(t, r, r.client(t, r.key), 4<<20)
	if m := r.tap.max.Load(); m <= MaxPayload || m > 1400 {
		t.Fatalf("largest datagram %d, want in (%d, 1400]", m, MaxPayload)
	}
}

func TestTCPManyStreams(t *testing.T) {
	r := newPoolRig(t, 0, false)
	cli := r.client(t, r.key)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			udpEcho(t, cli, 100+(i%10)*20000, byte(i))
		}(i)
	}
	waitOrFail(t, &wg, 30*time.Second)
}

func TestTCPTwoClientsSameKey(t *testing.T) {
	r := newPoolRig(t, 0, false)
	a, b := r.client(t, r.key), r.client(t, r.key)
	var wg sync.WaitGroup
	for i, c := range []*Session{a, b} {
		wg.Add(1)
		go func(i int, c *Session) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				udpEcho(t, c, 600000, byte(10*i+j))
			}
		}(i, c)
	}
	waitOrFail(t, &wg, 30*time.Second)
	if n := r.srv.Sessions(); n != 2 {
		t.Fatalf("server has %d sessions, want 2", n)
	}
	if n := r.ps.Pools(); n != 2 {
		t.Fatalf("server has %d pools, want 2", n)
	}
}

func TestTCPRejectsForeignKey(t *testing.T) {
	r := newPoolRig(t, 0, false)
	bad := r.client(t, []byte("other-key"))
	st, err := bad.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	st.Write([]byte("Ehello"))
	time.Sleep(500 * time.Millisecond)
	if n := r.srv.Sessions(); n != 0 {
		t.Fatalf("server admitted %d sessions from a foreign key", n)
	}
	udpEcho(t, r.client(t, r.key), 50000, 1)
}

func TestTCPKillConnsMidTransfer(t *testing.T) {
	r := newPoolRig(t, 0, false)
	pio := r.pio(t)
	cli, err := NewSession(Config{Key: r.key}, pio)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	stop := make(chan struct{})
	go func() {
		for _, d := range []time.Duration{150, 400} {
			select {
			case <-time.After(d * time.Millisecond):
				r.ps.kill(3)
			case <-stop:
				return
			}
		}
	}()
	poolBulk(t, r, cli, 6<<20)
	close(stop)
	deadline := time.Now().Add(5 * time.Second)
	for pio.Conns() < 8 || r.ps.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: client %d, server %d conns", pio.Conns(), r.ps.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTCPNoGoroutineLeak(t *testing.T) {
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	for _, useTLS := range []bool{false, true} {
		r := newPoolRig(t, 0, useTLS)
		cli := r.client(t, r.key)
		udpEcho(t, cli, 200000, 5)
		cli.Close()
		r.srv.Close()
	}
	var n int
	for i := 0; i < 50; i++ {
		if n = runtime.NumGoroutine(); n <= base+2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	t.Fatalf("goroutines %d, baseline %d\n%s", n, base, buf[:runtime.Stack(buf, true)])
}

func TestTLSPinAndTLS13(t *testing.T) {
	r := newPoolRig(t, 0, true)
	// wrong pin: the pool never comes up
	bad, err := NewTLSPoolClient(r.addr, 2, TLSClientOptions{PinSHA256: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	time.Sleep(600 * time.Millisecond)
	if bad.Conns() != 0 {
		t.Fatal("client connected despite a wrong pin")
	}
	// plain TLS 1.2 is refused by the server
	c, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	if err == nil {
		c.Close()
		t.Fatal("server accepted TLS 1.2")
	}
}
