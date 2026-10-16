//go:build !linux

package wat

import "net"

func setNotsentLowat(*net.TCPConn, int) {}

func setCongestion(*net.TCPConn, string) string { return "" }
