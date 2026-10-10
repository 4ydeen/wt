package wat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// revIran is the Iran side of a reverse pool: a listener (merged pool) plus the session client on top of it.
type revIran struct {
	ps  *TCPPoolServer
	io  *ReverseListenIO
	cli *Session
}

func revListen(t *testing.T, flavor, addr string, key []byte) *revIran {
	t.Helper()
	var ps *TCPPoolServer
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for { // a restart rebinds the same port: allow the old socket a moment to go away
		switch flavor {
		case "ws":
			ps, err = NewWSPoolServer(addr, HTTPServerOptions{Path: "/wat"})
		default:
			ps, err = NewTCPPoolServer(addr)
		}
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	rio := NewReverseListenIO(ps)
	cli, err := NewSession(Config{Key: key}, rio)
	if err != nil {
		t.Fatal(err)
	}
	r := &revIran{ps: ps, io: rio, cli: cli}
	t.Cleanup(r.stop)
	return r
}

func (r *revIran) stop() { r.cli.Close(); r.io.Close() }

// revKharej is the Kharej side: a session server whose RawIO dials the Iran listener out.
func revKharej(t *testing.T, flavor, addr string, key []byte) (*Server, *ReverseDialRaw) {
	t.Helper()
	var c *TCPPoolClient
	var err error
	switch flavor {
	case "ws":
		c, err = NewWSPoolClient(addr, 8, HTTPClientOptions{Path: "/wat", Host: "cdn.example.com"})
	default:
		c, err = NewTCPPoolClient(addr, 8)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw := NewReverseDialRaw(c)
	srv := NewServer(Config{Key: key}, raw)
	srv.IdleTimeout = 5 * time.Second
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-srv.New:
				go func(s *Session) {
					for {
						st, err := s.Accept()
						if err != nil {
							return
						}
						go serveUDPStream(st)
					}
				}(s)
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); srv.Close() })
	return srv, raw
}

func revBulk(t *testing.T, cli *Session, n int) {
	t.Helper()
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
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func revBulkTest(t *testing.T, flavor string) {
	key := []byte("rev-key")
	ir := revListen(t, flavor, "127.0.0.1:0", key)
	revKharej(t, flavor, ir.io.Addr().String(), key)
	t0 := time.Now()
	revBulk(t, ir.cli, 4<<20)
	t.Logf("%s reverse 4 MiB up+down in %v", flavor, time.Since(t0))
}

func TestReverseTCPBulk(t *testing.T) { revBulkTest(t, "tcp") }
func TestReverseWSBulk(t *testing.T)  { revBulkTest(t, "ws") }

// The Iran side restarts (new listener on the same port, new session): the Kharej side redials by itself and a
// new session's streams work.
func TestReverseListenerRestart(t *testing.T) {
	for _, flavor := range []string{"tcp", "ws"} {
		key := []byte("rev-key")
		addr := freeAddr(t)
		ir := revListen(t, flavor, addr, key)
		_, raw := revKharej(t, flavor, addr, key)
		revBulk(t, ir.cli, 1<<20)
		ir.stop()
		for end := time.Now().Add(time.Second); raw.Conns() != 0 && time.Now().Before(end); {
			time.Sleep(10 * time.Millisecond)
		}
		ir2 := revListen(t, flavor, addr, key)
		deadline := time.Now().Add(10 * time.Second)
		for ir2.io.Conns() < 8 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: server did not redial: %d conns", flavor, ir2.io.Conns())
			}
			time.Sleep(50 * time.Millisecond)
		}
		revBulk(t, ir2.cli, 1<<20)
	}
}

func TestReverseKillConnsMidTransfer(t *testing.T) {
	key := []byte("rev-key")
	ir := revListen(t, "tcp", "127.0.0.1:0", key)
	_, raw := revKharej(t, "tcp", ir.io.Addr().String(), key)
	stop := make(chan struct{})
	go func() {
		for _, d := range []time.Duration{150, 400} {
			select {
			case <-time.After(d * time.Millisecond):
				ir.ps.kill(3)
			case <-stop:
				return
			}
		}
	}()
	revBulk(t, ir.cli, 6<<20)
	close(stop)
	deadline := time.Now().Add(8 * time.Second)
	for raw.Conns() < 8 || ir.io.Conns() < 8 {
		if time.Now().After(deadline) {
			t.Fatalf("pool did not recover: dialer %d, listener %d", raw.Conns(), ir.io.Conns())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
