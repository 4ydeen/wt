//go:build !linux

package wat

import "net"

func setNotsentLowat(*net.TCPConn, int) {}
