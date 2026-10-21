package wat

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// kexWait polls until fn turns true: the exchange runs on the pump timers, not synchronously with the writes.
func kexWait(t *testing.T, what string, fn func() bool) {
	t.Helper()
	for i := 0; i < 2500; i++ {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("kex: %s did not happen", what)
}

// The offer rides the client's first packet (sealed with the PSK key), the reply switches the client at once and a
// fresh-key packet from the client then switches the server. Data written on both sides of the switch must arrive.
func TestKexSwitch(t *testing.T) {
	cli, srv := memPair(t, Config{})
	var total int64
	go func() {
		s, err := srv.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 8192)
		for {
			n, err := s.Read(buf)
			atomic.AddInt64(&total, int64(n))
			if err != nil {
				return
			}
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte{0xA5}, 4000)
	if _, err := st.Write(first); err != nil { // sealed with the PSK key; the offer rides along
		t.Fatal(err)
	}
	kexWait(t, "the client to switch", func() bool { cli.mu.Lock(); defer cli.mu.Unlock(); return cli.kexDone })
	kexWait(t, "the server to switch", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return srv.kexDone })
	if _, err := st.Write(bytes.Repeat([]byte{0x5A}, 4000)); err != nil { // sealed with the fresh key
		t.Fatal(err)
	}
	st.CloseWrite()
	kexWait(t, "the peer to receive everything", func() bool { return atomic.LoadInt64(&total) == 8000 })

	// a packet sealed with the fresh key must not open with the PSK key any more
	cli.mu.Lock()
	out, pn := cli.seal([]byte{frPing})
	fresh := cli.aead
	cli.mu.Unlock()
	psk, _ := sessionAEAD([]byte("bench-key"), cli.sid)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], pn)
	if _, err := psk.Open(nil, nonce[:], out[hdrLen:], out[:8]); err == nil {
		t.Fatal("a fresh-key packet still opens with the PSK key")
	}
	if _, err := fresh.Open(nil, nonce[:], out[hdrLen:], out[:8]); err != nil {
		t.Fatalf("the fresh key does not open its own packet: %v", err)
	}
}

// kexGrace after the switch the PSK key stops authenticating anything.
func TestKexGraceDrop(t *testing.T) {
	cli, srv := memPair(t, Config{})
	cli.mu.Lock()
	cli.kexGrace = 30 * time.Millisecond // per-session field: shrinking a package global would race other pumps
	cli.mu.Unlock()
	srv.mu.Lock()
	srv.kexGrace = 30 * time.Millisecond
	srv.mu.Unlock()
	go func() {
		s, err := srv.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, s)
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	kexWait(t, "both switches", func() bool {
		cli.mu.Lock(); c := cli.kexDone && cli.oldAead != nil; cli.mu.Unlock()
		srv.mu.Lock(); s := srv.kexDone && srv.oldAead != nil; srv.mu.Unlock()
		return c && s
	})
	kexWait(t, "the old keys to expire", func() bool {
		cli.mu.Lock(); c := cli.oldAead == nil; cli.mu.Unlock()
		srv.mu.Lock(); s := srv.oldAead == nil; srv.mu.Unlock()
		return c && s
	})
}

// A 2.9.x server has no ephemeral key: it ignores the frKex frame, the client keeps offering (re-armed with
// fresh keys once a round times out), and the session stays on the PSK key exactly as before.
func TestKexOldPeer(t *testing.T) {
	cli, srv := memPair(t, Config{})
	cli.mu.Lock()
	cli.kexGiveUp = 50 * time.Millisecond // per-session field, not the package global (other pumps read it)
	oldPub := append([]byte(nil), cli.kexPub...)
	cli.mu.Unlock()
	srv.mu.Lock()
	srv.kexPriv, srv.kexPub = nil, nil
	srv.mu.Unlock()
	var total int64
	go func() {
		s, err := srv.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 8192)
		for {
			n, err := s.Read(buf)
			atomic.AddInt64(&total, int64(n))
			if err != nil {
				return
			}
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(bytes.Repeat([]byte{7}, 1000)); err != nil {
		t.Fatal(err)
	}
	st.CloseWrite()
	kexWait(t, "the data to arrive", func() bool { return atomic.LoadInt64(&total) == 1000 })
	kexWait(t, "the client to re-arm with fresh keys", func() bool {
		cli.mu.Lock(); defer cli.mu.Unlock()
		return cli.kexPriv != nil && !cli.kexDone && !bytes.Equal(cli.kexPub, oldPub)
	})
	cli.mu.Lock()
	defer cli.mu.Unlock()
	if cli.oldAead != nil {
		t.Fatal("client switched keys against an old peer")
	}
}

// A 2.9.x client never offers: the server never replies and stays on the PSK key.
// NoKex is set at NewSession — stripping kexPriv after the pair is up would race the client's
// birth offer (kexPending emits one on the first packet), which under -race reached the server
// and engaged it before the strip.
func TestKexOldClient(t *testing.T) {
	a, b := newMemDir(), newMemDir()
	cc := Config{Key: []byte("bench-key"), SID: 0x1234567, InitBps: 400e6, MaxBps: 400e6, NoKex: true}
	sc := cc
	sc.Server = true
	sc.NoKex = false // the server stays kex-capable: it must not react even though it could
	cli, err := NewSession(cc, &memIO{tx: a, rx: b, done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewSession(sc, &memIO{tx: b, rx: a, done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); srv.Close() })
	var total int64
	go func() {
		s, err := srv.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 8192)
		for {
			n, err := s.Read(buf)
			atomic.AddInt64(&total, int64(n))
			if err != nil {
				return
			}
		}
	}()
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(bytes.Repeat([]byte{9}, 1000)); err != nil {
		t.Fatal(err)
	}
	st.CloseWrite()
	kexWait(t, "the data to arrive", func() bool { return atomic.LoadInt64(&total) == 1000 })
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.kexAead != nil || srv.kexReplyPend || srv.kexDone {
		t.Fatal("the server must not react without an offer")
	}
}

// A peer public key of low order yields the all-zero shared secret: the exchange ends, the PSK key stays.
func TestKexBadPeerKey(t *testing.T) {
	_, srv := memPair(t, Config{})
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.onKex(make([]byte, 32), time.Now())
	if srv.kexPriv != nil || srv.kexAead != nil || srv.kexReplyPend {
		t.Fatal("a low-order peer key must end the exchange without touching the session keys")
	}
}

// A server whose client never switches stops paying one failed fresh-key open per packet: kexAead
// expires kexGrace after the last offer, and the client's next offer (fresh keys, new pub) re-engages.
func TestKexServerAeadExpiry(t *testing.T) {
	cli, srv := memPair(t, Config{})
	defer cli.Close()
	defer srv.Close()
	privB := make([]byte, 32)
	if _, err := crand.Read(privB); err != nil {
		t.Fatal(err)
	}
	pubB, err := curve25519.X25519(privB, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.kexGrace = 30 * time.Millisecond // per-session field: a global would race the live pumps (seen under -race)
	srv.onKex(cli.kexPub, now)           // first offer engages the fresh key; the reply never lands
	if srv.kexAead == nil || srv.kexPeerPub == nil {
		t.Fatal("offer did not engage the fresh key")
	}
	srv.timers(now.Add(2 * srv.kexGrace)) // no switch, no further offers: drop the stale exchange
	if srv.kexAead != nil || srv.kexPeerPub != nil || srv.kexDone {
		t.Fatal("stale kexAead did not expire")
	}
	srv.onKex(pubB, now.Add(3*srv.kexGrace)) // the re-armed client offers a new pub
	if srv.kexAead == nil || !bytes.Equal(srv.kexPeerPub, pubB) || !srv.kexReplyPend {
		t.Fatal("re-armed offer did not re-engage")
	}
}
