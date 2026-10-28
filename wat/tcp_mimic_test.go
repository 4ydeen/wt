package wat

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMimicHello(t *testing.T) {
	psk := []byte("mimic-key")
	id := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	h, ctx, crx, err := buildMimicHello(psk, "", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != mimicHelloLen || !isMimicPrefix(h) {
		t.Fatalf("hello is %d bytes, prefix %x", len(h), h[:5])
	}
	h2, _, _, _ := buildMimicHello(psk, "", id)
	if bytes.Equal(h[11:76], h2[11:76]) {
		t.Fatal("two hellos for one pool id carry the same auth bytes")
	}
	got, ltx, lrx, ok := parseMimicHello(psk, h)
	if !ok || got != id {
		t.Fatalf("hello does not verify: ok=%v id=%x", ok, got)
	}
	if _, _, _, ok := parseMimicHello([]byte("other"), h); ok {
		t.Fatal("hello verifies under another key")
	}
	bad := append([]byte(nil), h...)
	bad[30] ^= 1
	if _, _, _, ok := parseMimicHello(psk, bad); ok {
		t.Fatal("tampered hello verifies")
	}
	// the dialer's tx mask is the listener's rx mask, and the other way round
	a, b := []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}
	ctx.XORKeyStream(a, a)
	lrx.XORKeyStream(b, b)
	if !bytes.Equal(a, b) {
		t.Fatal("dialer tx mask differs from listener rx mask")
	}
	a, b = []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}
	crx.XORKeyStream(a, a)
	ltx.XORKeyStream(b, b)
	if !bytes.Equal(a, b) {
		t.Fatal("dialer rx mask differs from listener tx mask")
	}
}

// spyListener relays every accepted connection to target and keeps the first n bytes the client sent on each.
type spyListener struct {
	ln    net.Listener
	mu    sync.Mutex
	heads [][]byte
}

func newSpy(t *testing.T, target string) *spyListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &spyListener{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go func() {
				defer c.Close()
				defer up.Close()
				head := make([]byte, 64)
				n, _ := io.ReadFull(c, head)
				s.mu.Lock()
				s.heads = append(s.heads, head[:n])
				s.mu.Unlock()
				up.Write(head[:n])
				io.Copy(up, c)
			}()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	return s
}

func (s *spyListener) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.heads...)
}

// poolPing sends packets both ways and fails if either direction does not arrive.
func poolPing(t *testing.T, cli *TCPPoolClient, srv *TCPPoolServer, within time.Duration) {
	t.Helper()
	up := bytes.Repeat([]byte("up"), 300)
	down := bytes.Repeat([]byte("dn"), 300)
	deadline := time.Now().Add(within)
	got := make(chan net.Addr, 1)
	go func() {
		for {
			p, _, src, err := srv.Recv()
			if err != nil {
				return
			}
			if bytes.Equal(p, up) {
				select {
				case got <- src:
				default:
				}
				return
			}
		}
	}()
	var src net.Addr
	for src == nil && time.Now().Before(deadline) {
		cli.Send(append([]byte(nil), up...), 0)
		select {
		case src = <-got:
		case <-time.After(100 * time.Millisecond):
		}
	}
	if src == nil {
		t.Fatalf("client packet did not reach the listener within %v", within)
	}
	back := make(chan bool, 1)
	go func() {
		for {
			p, _, _, err := cli.Recv()
			if err != nil {
				return
			}
			if bytes.Equal(p, down) {
				back <- true
				return
			}
		}
	}()
	for {
		srv.SendTo(append([]byte(nil), down...), 0, src)
		select {
		case <-back:
			return
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatalf("listener packet did not reach the client within %v", within)
			}
		}
	}
}

func TestTCPMimicPool(t *testing.T) {
	psk := []byte("pool-mimic")
	srv, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetObfs(psk)
	spy := newSpy(t, srv.Addr().String())
	cli, err := NewTCPPoolClient(spy.ln.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.SetObfs(psk, "example.org")
	poolPing(t, cli, srv, 5*time.Second)
	heads := spy.snapshot()
	if len(heads) == 0 {
		t.Fatal("no connection seen")
	}
	for i, h := range heads {
		if !isMimicPrefix(h) {
			t.Fatalf("connection %d starts with %x, not a TLS record header", i, h[:min(8, len(h))])
		}
	}
	if len(heads) > 1 && bytes.Equal(heads[0][11:], heads[1][11:]) {
		t.Fatal("two connections of one pool open with the same bytes")
	}
}

// -sessions N builds extra pools with Clone; the clone must carry the hello v2 setup along. The server accepts a
// plain pool id too (old clients), so the check is on the clone's own state, which slotLoop reads.
func TestTCPMimicClone(t *testing.T) {
	psk := []byte("pool-clone")
	srv, err := NewTCPPoolServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetObfs(psk)
	cli, err := NewTCPPoolClient(srv.Addr().String(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.SetObfs(psk, "example.org")
	clone, err := cli.Clone(0)
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	if o := clone.obf.Load(); o == nil || !clone.v2.Load() {
		t.Fatal("the clone lost the hello v2 setup: its connections would open with the plain pool id")
	}
	poolPing(t, clone, srv, 5*time.Second)
}

func TestTCPMimicCompat(t *testing.T) {
	old, oldF := mimicFallback, mimicLater
	mimicFallback, mimicLater = 600*time.Millisecond, 10*time.Second
	defer func() { mimicFallback, mimicLater = old, oldF }()
	psk := []byte("pool-compat")
	t.Run("new client, old listener", func(t *testing.T) {
		srv, err := NewTCPPoolServer("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		cli, err := NewTCPPoolClient(srv.Addr().String(), 2)
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		cli.SetObfs(psk, "")
		poolPing(t, cli, srv, 10*time.Second)
	})
	t.Run("old client, new listener", func(t *testing.T) {
		srv, err := NewTCPPoolServer("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		srv.SetObfs(psk)
		cli, err := NewTCPPoolClient(srv.Addr().String(), 2)
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		poolPing(t, cli, srv, 5*time.Second)
	})
	t.Run("wrong key is refused", func(t *testing.T) {
		srv, err := NewTCPPoolServer("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		srv.SetObfs(psk)
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		h, _, _, _ := buildMimicHello([]byte("not the key"), "", [8]byte{9})
		c.Write(h)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := c.Read(make([]byte, 16)); err == nil || n > 0 {
			t.Fatalf("listener answered a hello under the wrong key (n=%d err=%v)", n, err)
		}
	})
}
