package wat

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// recClient records every datagram a client sends (a copy, as sent on the wire).
type recClient struct {
	PacketIO
	mu   sync.Mutex
	pkts [][]byte
}

func (c *recClient) Send(p []byte, path int) error {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.PacketIO.Send(p, path)
}

func (c *recClient) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.pkts...)
}

// maskRig is a loopback UDP server plus one recording client, each with its own Config.
func maskRig(t *testing.T, srvCfg, cliCfg Config) (*Session, *recClient) {
	t.Helper()
	us, err := NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("mask-key")
	srvCfg.Key = key
	srv := NewServer(srvCfg, us)
	t.Cleanup(srv.Close)
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
	uc, err := NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recClient{PacketIO: uc}
	cliCfg.Key = key
	cli, err := NewSession(cliCfg, rec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	return cli, rec
}

func TestMaskHdrInvolution(t *testing.T) {
	key := hdrMaskKey([]byte("k"))
	p := make([]byte, 64)
	for i := range p {
		p[i] = byte(i * 7)
	}
	orig := append([]byte(nil), p...)
	maskHdr(key, p)
	if bytes.Equal(p[:hdrLen], orig[:hdrLen]) || !bytes.Equal(p[hdrLen:], orig[hdrLen:]) {
		t.Fatal("mask must change the header and only the header")
	}
	if h := unmaskedHdr(key, p); !bytes.Equal(h[:], orig[:hdrLen]) {
		t.Fatal("unmaskedHdr does not undo maskHdr")
	}
	maskHdr(key, p)
	if !bytes.Equal(p, orig) {
		t.Fatal("masking twice is not the identity")
	}
}

// Two new peers: no datagram carries the session id, and no two headers share a byte pattern.
func TestHdrMaskedOnTheWire(t *testing.T) {
	cli, rec := maskRig(t, Config{}, Config{PingEvery: 50 * time.Millisecond})
	udpEcho(t, cli, 200000, 1)
	pkts := rec.snapshot()
	if len(pkts) < 20 {
		t.Fatalf("only %d packets sent", len(pkts))
	}
	sid := make([]byte, 8)
	binary.BigEndian.PutUint64(sid, cli.sid)
	seen := map[uint64]bool{}
	for i, p := range pkts {
		if bytes.Equal(p[:8], sid) {
			t.Fatalf("packet %d carries the session id in clear", i)
		}
		seen[binary.BigEndian.Uint64(p)] = true
	}
	if len(seen) != len(pkts) {
		t.Fatalf("%d packets but %d distinct first words", len(pkts), len(seen))
	}
}

// A server that predates masking (NoMask stands in for it) must still be served by a new client, and a masking
// server must still serve an old client.
func TestHdrMaskCompat(t *testing.T) {
	t.Run("new client, old server", func(t *testing.T) {
		cli, _ := maskRig(t, Config{NoMask: true}, Config{})
		t0 := time.Now()
		udpEcho(t, cli, 50000, 2)
		t.Logf("first echo after %v", time.Since(t0))
	})
	t.Run("old client, new server", func(t *testing.T) {
		cli, rec := maskRig(t, Config{}, Config{NoMask: true})
		udpEcho(t, cli, 50000, 3)
		sid := make([]byte, 8)
		binary.BigEndian.PutUint64(sid, cli.sid)
		for _, p := range rec.snapshot() {
			if !bytes.Equal(p[:8], sid) {
				t.Fatal("an unmasked client sent a masked header")
			}
		}
	})
	t.Run("new peers, mask off on one side", func(t *testing.T) {
		cli, _ := maskRig(t, Config{}, Config{NoMask: true, NoShape: true})
		udpEcho(t, cli, 50000, 4)
	})
}

// Idle traffic is no longer one fixed packet size at a fixed interval.
func TestIdleShape(t *testing.T) {
	cli, rec := maskRig(t, Config{}, Config{PingEvery: 40 * time.Millisecond})
	udpEcho(t, cli, 1000, 5)
	n0 := len(rec.snapshot())
	time.Sleep(1500 * time.Millisecond)
	sizes := map[int]bool{}
	for _, p := range rec.snapshot()[n0:] {
		sizes[len(p)] = true
	}
	if len(sizes) < 8 {
		t.Fatalf("idle packets use only %d distinct sizes", len(sizes))
	}
}

func TestNoShapeKeepsSizeFixed(t *testing.T) {
	cli, rec := maskRig(t, Config{NoShape: true}, Config{PingEvery: 40 * time.Millisecond, NoShape: true})
	udpEcho(t, cli, 1000, 6)
	n0 := len(rec.snapshot())
	time.Sleep(600 * time.Millisecond)
	sizes := map[int]bool{}
	for _, p := range rec.snapshot()[n0:] {
		sizes[len(p)] = true
	}
	if len(sizes) > 3 {
		t.Fatalf("NoShape idle packets vary over %d sizes", len(sizes))
	}
}
