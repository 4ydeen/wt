//go:build !linux

package wat

import (
	"net"
	"time"
)

func setNotsentLowat(*net.TCPConn, int) {}

func setCongestion(*net.TCPConn, string) string { return "" }

func setUserTimeout(*net.TCPConn, time.Duration) {}
