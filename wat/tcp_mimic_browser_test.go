package wat

import (
	"bytes"
	"testing"
)

// TestMimicBrowserHello: the dialer's hello is a real browser hello (shuffled extension order, so no single JA3) that the
// listener still parses, and a hello that utls cannot make 517 bytes falls back to the fixed one (3.0.1).
func TestMimicBrowserHello(t *testing.T) {
	psk := []byte("psk-for-the-test")
	orders := map[string]bool{}
	for i := 0; i < 40; i++ {
		id := [8]byte{1, 2, 3, 4, 5, 6, 7, byte(i)}
		hello, _, _, err := buildMimicHello(psk, "www.example.com", id)
		if err != nil || len(hello) != mimicHelloLen || !isMimicPrefix(hello) {
			t.Fatalf("hello %d: len %d err %v", i, len(hello), err)
		}
		got, _, _, ok := parseMimicHello(psk, hello)
		if !ok || got != id {
			t.Fatalf("hello %d does not parse back (ok=%v)", i, ok)
		}
		if !bytes.Contains(hello, []byte("www.example.com")) {
			t.Fatal("no SNI in the hello")
		}
		orders[string(hello[78:140])] = true // the cipher suites and the first extensions: GREASE and shuffling vary them
	}
	if len(orders) < 5 {
		t.Fatalf("only %d distinct hello shapes in 40 connections: the fingerprint is not varying", len(orders))
	}
	long := string(bytes.Repeat([]byte("a"), 190)) + ".com"
	hello, _, _, err := buildMimicHello(psk, long, [8]byte{9})
	if err != nil || len(hello) != mimicHelloLen {
		t.Fatalf("long SNI: len %d err %v", len(hello), err)
	}
	if _, _, _, ok := parseMimicHello(psk, hello); !ok {
		t.Fatal("long SNI hello does not parse")
	}
}
