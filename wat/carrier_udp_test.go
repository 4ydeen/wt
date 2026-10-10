package wat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sizeTap records the largest datagram sent through a carrier.
type sizeTap struct {
	max atomic.Int64
}

func (t *sizeTap) note(n int) {
	for {
		o := t.max.Load()
		if int64(n) <= o || t.max.CompareAndSwap(o, int64(n)) {
			return
		}
	}
}

type tapClient struct {
	PacketIO
	t *sizeTap
}

func (c tapClient) Send(p []byte, path int) error { c.t.note(len(p)); return c.PacketIO.Send(p, path) }

type tapServer struct {
	RawIO
	t *sizeTap
}

// Profile forwards only Reliable (the other fields would change the datagram size these tests pin; embedding the RawIO interface would hide it, and a pool server would
// then run as an unreliable carrier).
func (s tapServer) Profile() Profile { return Profile{Reliable: profileOf(s.RawIO).Reliable} }

func (s tapServer) SendTo(p []byte, lane int, dst net.Addr) error {
	s.t.note(len(p))
	return s.RawIO.SendTo(p, lane, dst)
}

// udpRig is a real Server on a loopback UDP socket. Stream protocol (first byte):
// 'E' echo, 'U' read to EOF then reply sha256, 'D'+uint32 n: send pattern(n, 7).
type udpRig struct {
	srv  *Server
	addr string
	tap  *sizeTap
	key  []byte
	mtu  int
}

func newUDPRig(t *testing.T, mtu int) *udpRig {
	t.Helper()
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &udpRig{addr: us.Addr().String(), tap: &sizeTap{}, key: []byte("udp-key"), mtu: mtu}
	srv := NewServer(Config{Key: r.key, MaxPayload: mtu}, tapServer{us, r.tap})
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

func serveUDPStream(st *Stream) {
	var h [1]byte
	if _, err := io.ReadFull(st, h[:]); err != nil {
		return
	}
	switch h[0] {
	case 'E':
		io.Copy(st, st)
	case 'U':
		hh := sha256.New()
		io.Copy(hh, st)
		st.Write(hh.Sum(nil))
	case 'D':
		var n [4]byte
		if _, err := io.ReadFull(st, n[:]); err != nil {
			return
		}
		st.Write(pattern(int(binary.BigEndian.Uint32(n[:])), 7))
	}
	st.CloseWrite()
}

func (r *udpRig) client(t *testing.T, key []byte) *Session {
	t.Helper()
	uc, err := NewUDPClient(r.addr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(Config{Key: key, MaxPayload: r.mtu}, tapClient{uc, r.tap})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func udpEcho(t *testing.T, cli *Session, n int, seed byte) {
	t.Helper()
	data := pattern(n, seed)
	st, err := cli.OpenStream()
	if err != nil {
		t.Error(err)
		return
	}
	go func() { st.Write(append([]byte{'E'}, data...)); st.CloseWrite() }()
	b, err := readAll(st)
	if err != nil || !bytes.Equal(b, data) {
		t.Errorf("echo seed %d: err=%v got %d want %d", seed, err, len(b), n)
	}
}

func udpBulk(t *testing.T, mtu int) {
	r := newUDPRig(t, mtu)
	cli := r.client(t, r.key)
	const n = 4 << 20
	t0 := time.Now()
	// upload
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
	// download
	t0 = time.Now()
	st, err = cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	req := []byte{'D', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(req[1:], n)
	go func() { st.Write(req); st.CloseWrite() }()
	got, err := readAll(st)
	if err != nil || !bytes.Equal(got, pattern(n, 7)) {
		t.Fatalf("download mismatch: err=%v got %d want %d", err, len(got), n)
	}
	t.Logf("mtu %d: up %v down %v, max datagram %d", mtu, tUp, time.Since(t0), r.tap.max.Load())
}

func TestUDPBulk(t *testing.T) { udpBulk(t, 0) }

func TestUDPManyStreams(t *testing.T) {
	r := newUDPRig(t, 0)
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

func TestUDPTwoClientsSameKey(t *testing.T) {
	r := newUDPRig(t, 0)
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
}

func TestUDPRejectsForeignKey(t *testing.T) {
	r := newUDPRig(t, 0)
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
	// the right key still works on the same socket
	udpEcho(t, r.client(t, r.key), 50000, 1)
}

func TestUDPLargeDatagrams(t *testing.T) {
	udpBulk(t, 1400)
	// rig is gone, so re-run to read the tap: use a fresh rig and check sizes explicitly
	r := newUDPRig(t, 1400)
	cli := r.client(t, r.key)
	udpEcho(t, cli, 1<<20, 9)
	if m := r.tap.max.Load(); m <= MaxPayload || m > 1400 {
		t.Fatalf("largest datagram %d, want in (%d, 1400]", m, MaxPayload)
	}
	// and the default stays at the ICMP-safe size
	r0 := newUDPRig(t, 0)
	udpEcho(t, r0.client(t, r0.key), 1<<20, 9)
	if m := r0.tap.max.Load(); m > MaxPayload {
		t.Fatalf("default config sent a %d byte datagram", m)
	}
}

func waitOrFail(t *testing.T, wg *sync.WaitGroup, d time.Duration) {
	t.Helper()
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatal("timeout")
	}
}
