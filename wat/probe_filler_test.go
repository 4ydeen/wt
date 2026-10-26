package wat

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestProbeFillerServersKeepReading: every carrier's real server takes the 32 KB probe filler and keeps the
// connection open past probeWait, so the probe's acked-bytes signal is not cut short by the server itself
// (3.0.0 review: the filler shapes were untested against the servers).
func TestProbeFillerServersKeepReading(t *testing.T) {
	servers := map[string]func() (*TCPPoolServer, error){
		"tcp": func() (*TCPPoolServer, error) { return NewTCPPoolServer("127.0.0.1:0") },
		"tls": func() (*TCPPoolServer, error) { return NewTLSPoolServer("127.0.0.1:0", "", "") },
		"ws":  func() (*TCPPoolServer, error) { return NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{}) },
		"wss": func() (*TCPPoolServer, error) {
			return NewWSPoolServer("127.0.0.1:0", HTTPServerOptions{Secure: true})
		},
		"h2c": func() (*TCPPoolServer, error) { return NewH2PoolServer("127.0.0.1:0", HTTPServerOptions{}) },
		"h2": func() (*TCPPoolServer, error) {
			return NewH2PoolServer("127.0.0.1:0", HTTPServerOptions{Secure: true})
		},
		"grpc": func() (*TCPPoolServer, error) {
			return NewGRPCPoolServer("127.0.0.1:0", HTTPServerOptions{Secure: true})
		},
	}
	for carrier, mk := range servers {
		t.Run(carrier, func(t *testing.T) {
			t.Parallel()
			s, err := mk()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.Dial("tcp4", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(probeWait + 500*time.Millisecond))
			if _, err := c.Write(probeFiller(carrier, "example.com", "")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 4096)
			for {
				_, err := c.Read(buf) // a TLS server answers the hello; any data is fine, a close is not
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
				if err != nil {
					t.Fatalf("server closed the probe connection before probeWait: %v", err)
				}
			}
		})
	}
}
