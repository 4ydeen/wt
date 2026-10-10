//go:build !linux

package wat

import "net"

// No recvmmsg / sendmmsg here: the UDP carrier uses one system call per datagram (SendBatch loops).
type udpBatch struct{}

func newUDPBatch(*net.UDPConn) *udpBatch { return nil }

func (*udpBatch) recv() ([]byte, net.Addr, error) { return nil, nil, net.ErrClosed }

func (*udpBatch) send([][]byte, net.Addr) error { return net.ErrClosed }
