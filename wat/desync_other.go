//go:build !linux

package wat

import (
	"errors"
	"net"
)

// The raw-packet half of the fake-SNI desync needs an AF_PACKET sniffer; only the Linux client (the Iran side)
// runs it, the same restriction as the ICMP carrier. Elsewhere NewDesync fails at startup, not silently.
func NewDesync(cfg DesyncConfig, peer string) (*Desync, error) {
	return nil, errors.New("wat: -fake-sni needs Linux with CAP_NET_RAW (the ICMP carrier's requirement)")
}

// Desync is the fake-SNI injector type; nothing constructs it off Linux.
type Desync struct{}

// Wrap exists so callers compile; NewDesync never returns a usable Desync off Linux.
func (d *Desync) Wrap(c net.Conn) (net.Conn, error) { return c, nil }
func (d *Desync) Close() error                      { return nil }
