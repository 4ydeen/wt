//go:build linux

package wat

import (
	"io"
	"net"
	"syscall"
	"testing"
)

// TestProbeOnceAckSignal: the probe calls a flow alive only when its filler is acknowledged. A receiver that keeps
// reading passes; one with a 4 KB window that stops reading (a stand-in for a filter that drops after a few KB)
// fails within probeWait.
func TestProbeOnceAckSignal(t *testing.T) {
	listen := func(rcvbuf int) net.Listener {
		lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
			if rcvbuf > 0 {
				c.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbuf) })
			}
			return nil
		}}
		ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		return ln
	}
	reading, stalled := listen(0), listen(4096)
	go func() {
		for {
			c, err := reading.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := stalled.Accept()
			if err != nil {
				return
			}
			held <- c // never read
		}
	}()
	for _, carrier := range []string{"tcp", "tls", "ws"} {
		f := probeFiller(carrier, "example.com", "")
		if ok, err := probeOnce(DesyncConfig{}, "none", reading.Addr().String(), "", f); err != nil || !ok {
			t.Fatalf("%s: reading peer: ok=%v err=%v, want alive", carrier, ok, err)
		}
	}
	if ok, err := probeOnce(DesyncConfig{}, "none", stalled.Addr().String(), "", probeFiller("tcp", "", "")); err != nil || ok {
		t.Fatalf("stalled peer: ok=%v err=%v, want cut", ok, err)
	}
}
