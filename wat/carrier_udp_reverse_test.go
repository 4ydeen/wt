package wat

import (
	"net"
	"testing"
	"time"
)

func TestPunchRoundTrip(t *testing.T) {
	k := punchKey([]byte("k"))
	p := makePunch(k)
	if !isPunch(k, p) {
		t.Fatal("a fresh punch does not verify")
	}
	if isPunch(punchKey([]byte("other")), p) {
		t.Fatal("a punch verifies under another key")
	}
	p[3] ^= 1
	if isPunch(k, p) {
		t.Fatal("a tampered punch verifies")
	}
	if isPunch(k, make([]byte, 40)) {
		t.Fatal("zeros verify as a punch")
	}
}

// The client binds and never sends first; once the server's punches arrive, the whole tunnel works.
func TestUDPReverse(t *testing.T) {
	key := []byte("rev-udp")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewUDPReverseServer("127.0.0.1:0", lis.Addr().String(), key)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Key: key}, rs)
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
	cli, err := NewSession(Config{Key: key}, lis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	udpEcho(t, cli, 500000, 8)
}

// Before a punch the client sends nothing anywhere; after a valid punch it answers to the punch's source.
func TestUDPReverseClientWaitsForPunch(t *testing.T) {
	key := []byte("rev-udp2")
	lis, err := NewUDPReverseListener("127.0.0.1:0", key)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewSession(Config{Key: key, PingEvery: 50 * time.Millisecond}, lis)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)
	f, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2048)
	f.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := f.ReadFromUDP(buf); err == nil {
		t.Fatal("client sent a datagram before any punch")
	}
	la := lis.Addr().(*net.UDPAddr)
	f.WriteToUDP(append([]byte("junk"), make([]byte, 40)...), la) // not a punch: must not make the client send
	f.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, _, err := f.ReadFromUDP(buf); err == nil {
		t.Fatal("client answered a datagram that is not a punch")
	}
	f.WriteToUDP(makePunch(punchKey(key)), la)
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := f.ReadFromUDP(buf); err != nil {
		t.Fatalf("client did not answer a valid punch: %v", err)
	}
}
