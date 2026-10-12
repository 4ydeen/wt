//go:build linux

package wat

import (
	"net"

	"golang.org/x/sys/unix"
)

// setNotsentLowat caps how much unsent data the kernel queues on a pool socket, so the writer blocks as soon as the
// connection stops moving instead of after megabytes of tcp_wmem (stall detection, carrier_tcp.go).
func setNotsentLowat(tc *net.TCPConn, n int) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n) })
}
