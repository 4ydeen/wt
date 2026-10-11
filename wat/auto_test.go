package wat

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// The "auto" layout: one bonded server on every carrier, with single-carrier clients (normal or reverse) on it.

func autoServe(srv *Server) {
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
}

func autoEcho(t *testing.T, cli *Session) {
	t.Helper()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := pattern(100000, 5)
	go func() { st.Write(append([]byte{'E'}, msg...)); st.CloseWrite() }()
	got, err := io.ReadAll(st)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: err=%v got %d want %d", err, len(got), len(msg))
	}
}

// wantClient requires a live client row on carrier whose IP is loopback and that was heard recently.
func wantClient(t *testing.T, srv *Server, carrier string) {
	t.Helper()
	for _, c := range srv.Clients() {
		if c.Carrier == carrier && c.IP == "127.0.0.1" && c.Age < 5*time.Second {
			return
		}
	}
	t.Fatalf("no client on %q from 127.0.0.1 in %+v", carrier, srv.Clients())
}

func TestServerBondedSingleCarrierClients(t *testing.T) {
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Path: "/wat"})
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("auto-direct")
	srv := NewServer(Config{Key: key}, NewMultiRaw([]string{"udp", "tcp", "ws"}, []RawIO{us, ts, ws}))
	t.Cleanup(srv.Close)
	go autoServe(srv)

	mk := func(name string) PacketIO {
		var p PacketIO
		var err error
		switch name {
		case "udp":
			p, err = NewUDPClient(us.Addr().String())
		case "tcp":
			p, err = NewTCPPoolClient(ts.Addr().String(), 4)
		case "ws":
			p, err = NewWSPoolClient(ws.Addr().String(), 4, HTTPClientOptions{Path: "/wat", Host: "cdn.example.com"})
		}
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, name := range []string{"tcp", "udp", "ws"} {
		cli, err := NewSession(Config{Key: key}, mk(name))
		if err != nil {
			t.Fatal(err)
		}
		autoEcho(t, cli)
		wantClient(t, srv, name)
		cli.Close()
	}
}

func TestReverseBondedServerSingleCarrierClient(t *testing.T) {
	key := []byte("auto-reverse")
	for _, flavor := range []string{"tcp", "ws"} {
		irTCP := revListen(t, "tcp", "127.0.0.1:0", key)
		irWS := revListen(t, "ws", "127.0.0.1:0", key)
		tc, err := NewTCPPoolClient(irTCP.io.Addr().String(), 4)
		if err != nil {
			t.Fatal(err)
		}
		wc, err := NewWSPoolClient(irWS.io.Addr().String(), 4, HTTPClientOptions{Path: "/wat", Host: "cdn.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		// a third child that dials a port nobody listens on (Iran picked another carrier): must just stay down
		dead, err := NewTCPPoolClient(freeAddr(t), 2)
		if err != nil {
			t.Fatal(err)
		}
		dead.SetMaxBackoff(30 * time.Second)
		srv := NewServer(Config{Key: key}, NewMultiRaw([]string{"tcp", "ws", "tls"},
			[]RawIO{NewReverseDialRaw(tc), NewReverseDialRaw(wc), NewReverseDialRaw(dead)}))
		go autoServe(srv)
		cli := irTCP.cli
		if flavor == "ws" {
			cli = irWS.cli
		}
		autoEcho(t, cli)
		wantClient(t, srv, flavor)
		srv.Close()
	}
}

func TestPoolDialLogThrottled(t *testing.T) {
	var n int
	c, err := NewTCPPoolClient(freeAddr(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	lines := make(chan string, 100)
	c.SetDialLog("tcp reverse dial", func(f string, a ...any) { lines <- f })
	time.Sleep(1500 * time.Millisecond) // many redials by now
	n = len(lines)
	if n != 1 {
		t.Fatalf("want exactly one failure line, got %d", n)
	}
}
