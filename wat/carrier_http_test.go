package wat

import (
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

// httpRig is a real Server on a loopback ws/wss/h2/h2c/grpc listener; the pool underneath is the tcp pool's.
type httpRig struct {
	*poolRig
	flavor string
	path   string
	stop   chan struct{}
	tlsOpt TLSClientOptions // client TLS tuning under test
}

// shut closes the server and the rig's accept goroutine (srv.New is never closed).
func (r *httpRig) shut() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.srv.Close()
}

func newHTTPPS(t *testing.T, flavor, path string) *TCPPoolServer {
	t.Helper()
	so := HTTPServerOptions{Path: path, Secure: flavor == "wss" || flavor == "h2" || flavor == "grpc"}
	var ps *TCPPoolServer
	var err error
	switch flavor {
	case "ws", "wss":
		ps, err = NewWSPoolServer("127.0.0.1:0", so)
	case "h2", "h2c":
		ps, err = NewH2PoolServer("127.0.0.1:0", so)
	case "grpc":
		ps, err = NewGRPCPoolServer("127.0.0.1:0", so)
	}
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func newHTTPRig(t *testing.T, flavor string) *httpRig {
	t.Helper()
	ps := newHTTPPS(t, flavor, "/wat")
	r := &poolRig{ps: ps, addr: ps.Addr().String(), tap: &sizeTap{}, key: []byte("pool-key")}
	srv := NewServer(Config{Key: r.key}, tapServer{ps, r.tap})
	srv.IdleTimeout = 5 * time.Second
	r.srv = srv
	stop := make(chan struct{})
	go func() {
		for {
			var s *Session
			select {
			case s = <-srv.New:
			case <-stop:
				return
			}
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
	hr := &httpRig{poolRig: r, flavor: flavor, path: "/wat", stop: stop}
	t.Cleanup(hr.shut)
	return hr
}

func (r *httpRig) pio(t *testing.T) *TCPPoolClient {
	t.Helper()
	o := HTTPClientOptions{Path: r.path, Host: "cdn.example.com", Headers: map[string]string{"X-Test": "1"},
		Secure: r.flavor == "wss" || r.flavor == "h2" || r.flavor == "grpc", TLS: r.tlsOpt}
	var c *TCPPoolClient
	var err error
	switch r.flavor {
	case "ws", "wss":
		c, err = NewWSPoolClient(r.addr, 8, o)
	case "h2", "h2c":
		c, err = NewH2PoolClient(r.addr, 8, o)
	case "grpc":
		c, err = NewGRPCPoolClient(r.addr, 8, o)
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *httpRig) client(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(Config{Key: r.key}, tapClient{r.pio(t), r.tap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestHTTPCarriersBulk(t *testing.T) {
	for _, f := range []string{"ws", "wss", "h2", "h2c", "grpc"} {
		t.Run(f, func(t *testing.T) {
			r := newHTTPRig(t, f)
			poolBulk(t, r.poolRig, r.client(t), 3<<20)
		})
	}
}

func TestWSManyStreams(t *testing.T) {
	r := newHTTPRig(t, "ws")
	cli := r.client(t)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			udpEcho(t, cli, 100+(i%10)*20000, byte(i))
		}(i)
	}
	waitOrFail(t, &wg, 9*time.Second)
}

func TestWSKillConnsMidTransfer(t *testing.T) {
	r := newHTTPRig(t, "ws")
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
	poolBulk(t, r.poolRig, cli, 4<<20)
	close(stop)
	deadline := time.Now().Add(5 * time.Second)
	for pio.Conns() < 8 || r.ps.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: client %d, server %d conns", pio.Conns(), r.ps.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWSNon404(t *testing.T) {
	r := newHTTPRig(t, "ws")
	base := "http://" + r.addr
	for _, p := range []string{"/", "/wat/x", "/other"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("GET %s = %d, want 404", p, resp.StatusCode)
		}
	}
	// the right path without upgrade headers looks the same, and so does an upgrade on the wrong path
	for _, p := range []string{"/wat", "/nope"} {
		req, _ := http.NewRequest("GET", base+p, nil)
		if p == "/nope" {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("GET %s = %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestHTTPNoGoroutineLeak(t *testing.T) {
	http.DefaultClient.CloseIdleConnections()
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	for _, f := range []string{"ws", "wss", "h2", "h2c", "grpc"} {
		r := newHTTPRig(t, f)
		cli := r.client(t)
		udpEcho(t, cli, 200000, 5)
		cli.Close()
		r.shut()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
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
