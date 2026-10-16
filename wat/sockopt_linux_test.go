//go:build linux

package wat

import (
	"net"
	"testing"
)

// setCongestion must report the socket's algorithm, and an unknown one must leave the socket working on the default.
func TestSetCongestion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	def := setCongestion(tc, "")
	if def == "" {
		t.Fatal("could not read TCP_CONGESTION")
	}
	if got := setCongestion(tc, "no-such-cc"); got != def {
		t.Fatalf("unknown algorithm: got %q, want the default %q", got, def)
	}
	got := setCongestion(tc, "bbr")
	t.Logf("default %q, after asking for bbr: %q", def, got)
	if got != "bbr" && got != def {
		t.Fatalf("bbr: got %q", got)
	}
	if _, err := c.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
}
