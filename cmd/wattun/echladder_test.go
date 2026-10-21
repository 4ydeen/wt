package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// TestDNSRelayGuardsAndRoundTrip: the built-in DNS relay (server target port 53, -ech ladder's second rung).
// Guard cases run against piped streams driven by a real session pair; the round trip runs end to end over
// the udp rig with a stub upstream.
func TestDNSRelayGuards(t *testing.T) {
	rig := newRelayRig(t)
	for _, tc := range []struct {
		name  string
		qlen  int
		short bool
	}{
		{"too short", 5, false},
		{"too long", 513, false},
		{"truncated", 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := rig.pick().OpenStream()
			if err != nil {
				t.Fatal(err)
			}
			defer st.Reset()
			hdr := [2]byte{0, 53}
			if _, err := st.Write(hdr[:]); err != nil {
				t.Fatal(err)
			}
			ql := [2]byte{byte(tc.qlen >> 8), byte(tc.qlen)}
			if _, err := st.Write(ql[:]); err != nil {
				t.Fatal(err)
			}
			if !tc.short {
				if _, err := st.Write(make([]byte, tc.qlen)); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := st.Write(make([]byte, tc.qlen-3)); err != nil {
					t.Fatal(err)
				}
			}
			st.CloseWrite() // a real client resets, but EOF releases the relay's ReadFull either way
			buf := make([]byte, 16)
			// the relay closes its write side without an answer; Read returns EOF once the FIN arrives
			if _, err := st.Read(buf); err == nil {
				t.Fatalf("%s: relay answered a bad query", tc.name)
			}
		})
	}
}

func TestDNSRelayRoundTrip(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback UDP")
	}
	defer pc.Close()
	go func() { // the stub upstream: echo the query with the QR bit set
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			ans := append([]byte(nil), buf[:n]...)
			ans[2] |= 0x80
			pc.WriteTo(ans, addr)
		}
	}()
	oldAddr, oldTimeout := dnsRelayUpstream, dnsRelayTimeout
	dnsRelayUpstream = pc.LocalAddr().String()
	dnsRelayTimeout = 3 * time.Second
	defer func() { dnsRelayUpstream, dnsRelayTimeout = oldAddr, oldTimeout }()

	rig := newRelayRig(t)
	ans, err := dialDNSRelay(rig, makeTestQuery())
	if err != nil {
		t.Fatalf("relay round trip: %v", err)
	}
	if binary.BigEndian.Uint16(ans[0:]) != 0x1234 || ans[2]&0x80 == 0 {
		t.Fatalf("not the stub's response: % x", ans[:4])
	}
}

// newRelayRig: the udp loopback rig whose server runs only the DNS relay handler.
func newRelayRig(t *testing.T) *tunnel {
	t.Helper()
	key := []byte("relay-key")
	us, err := wat.NewUDPServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := wat.NewServer(wat.Config{Key: key}, us)
	t.Cleanup(srv.Close)
	go func() {
		for s := range srv.New {
			go func() {
				for {
					st, err := s.Accept()
					if err != nil {
						return
					}
					go func() {
						var hdr [2]byte
						if _, err := readStreamFull(st, hdr[:]); err != nil {
							st.Reset()
							return
						}
						if binary.BigEndian.Uint16(hdr[:]) == dnsRelayPort {
							serveDNSRelay(st)
						} else {
							st.Reset()
						}
					}()
				}
			}()
		}
	}()
	uc, err := wat.NewUDPClient(us.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := wat.NewSession(wat.Config{Key: key}, uc)
	if err != nil {
		t.Fatal(err)
	}
	tun := newTunnel([]*wat.Session{s})
	t.Cleanup(tun.Close)
	waitFor(t, "relay session alive", 5*time.Second, s.Alive)
	return tun
}

func makeTestQuery() []byte {
	q := make([]byte, 20)
	binary.BigEndian.PutUint16(q[0:], 0x1234) // id
	return q
}

// readStreamFull/io-shape helper: wat.Stream satisfies io.Reader, so io.ReadFull works on it.
func readStreamFull(st *wat.Stream, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := st.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// relayFor: the built-in relay owns target 53 by default and under an explicit list that omits 53; an
// explicit list WITH 53 forwards it to the real local resolver instead. Before the 2026-10-21 audit fix
// the default 1-65535 range hit the same forwarding path (ok(53) was true), so the ladder's relay rung
// was dead on every default-config server.
func TestRelayFor(t *testing.T) {
	def := newAllow("", "")
	if !def.relayFor(53, 1, 65535) {
		t.Fatal("default range must leave the relay rung alive")
	}
	expl := newAllow("22,80,443", "")
	if !expl.relayFor(53, 1, 65535) {
		t.Fatal("explicit list without 53 must leave the relay alive")
	}
	fwd := newAllow("22,53,443", "")
	if fwd.relayFor(53, 1, 65535) {
		t.Fatal("explicit 53 forwards to the local resolver, not the relay")
	}
	fwd.setPorts([]int{53}) // cfg-authoritative list with 53
	if fwd.relayFor(53, 1, 65535) {
		t.Fatal("config list with 53 forwards to the local resolver")
	}
}
