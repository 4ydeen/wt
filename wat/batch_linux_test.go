//go:build linux

package wat

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestUDPGSORoundTrip: a GSO batch (runs of equal sizes, a shorter tail, a lone odd size) arrives as the same
// datagrams, in order, through a GRO receiver (3.0.0, WAT_GSO=1).
func TestUDPGSORoundTrip(t *testing.T) {
	t.Setenv("WAT_BATCH", "1")
	old := gsoWanted
	gsoWanted = true
	defer func() { gsoWanted = old }()
	rc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	sc, err := net.DialUDP("udp", nil, rc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	tx, rx := newUDPBatch(sc), newUDPBatch(rc)
	var ps [][]byte
	for i, n := range []int{1400, 1400, 1400, 1400, 900, 333, 1400, 1400, 70} {
		ps = append(ps, bytes.Repeat([]byte{byte(i + 1)}, n))
	}
	if err := tx.send(ps, nil); err != nil {
		t.Fatalf("send: %v (gso still on: %v)", err, tx.gso.Load())
	}
	rc.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i, want := range ps {
		got, _, err := rx.recv()
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("datagram %d: %d bytes of %d, want %d bytes of %d", i, len(got), got[0], len(want), want[0])
		}
	}
	t.Logf("gso on after the batch: %v, gro: %v", tx.gso.Load(), rx.rx.gro)
}
