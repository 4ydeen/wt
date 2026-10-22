//go:build linux

package wat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Raw injection of the fake ClientHello (see desync.go): one AF_PACKET sniffer watches every IPv4 TCP packet of
// the host and advances the portable tracker. Requires CAP_NET_RAW, like the ICMP carrier.
//
// Wrap announces each pool connection the moment dial returns. The stream start is probed off the socket with
// TCP_REPAIR + TCP_QUEUE_SEQ (the only kernel interface that reports a socket's sequence numbers; TCP_INFO does
// not carry one), so the fake normally fires on the handshake's final ACK — before any real data — even when the
// sniffer missed the SYN/SYN-ACK. When the probe fails (needs CAP_NET_ADMIN), Wrap announces the key with
// isnKnown=false and the tracker fires anchored to the first outbound data segment instead (the late path of
// desync.go). A 2 s timeout releases a Wrap whose handshake was never observed: the tunnel still works, it is
// just unclassified.

// desyncWrapTimeout bounds how long Wrap waits for the fake before giving up on classification.
const desyncWrapTimeout = 2 * time.Second

// tcpStreamBase returns the socket's send-queue sequence number (SND.NXT) as the stream-start anchor for the
// tracker. TCP_REPAIR freezes the socket's queues without touching its buffers; TCP_REPAIR_QUEUE selects the
// send queue and TCP_QUEUE_SEQ then reports its sequence number. ok false = probe unavailable (it needs
// CAP_NET_ADMIN): the tracker falls back to the wire-learned ISN (our outgoing SYN) or its late path.
func tcpStreamBase(tc *net.TCPConn) (nxt uint32, ok bool) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var serr error
	verr := raw.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, 1); serr != nil {
			return
		}
		defer func() { _ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, 0) }()
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, 1 /* TCP_SEND_QUEUE */); serr != nil {
			return
		}
		// x/sys/unix has no TCP_QUEUE_SEQ getsockopt wrapper; the raw getsockopt is 4 bytes, host order
		var b [4]byte
		l := uint32(4)
		if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.IPPROTO_TCP), unix.TCP_QUEUE_SEQ,
			uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0); errno != 0 {
			serr = errno
			return
		}
		nxt = binary.LittleEndian.Uint32(b[:])
	})
	if verr != nil || serr != nil || nxt == 0 {
		return 0, false
	}
	return nxt, true
}

// Desync is the fake-SNI injector of one client process: created once with NewDesync, every pool connection
// passes through Wrap after the kernel handshake.
type Desync struct {
	inj *desyncInjector
}

// NewDesync starts the sniffer for the peer (host:port or IP). Linux only; needs CAP_NET_RAW.
func NewDesync(cfg DesyncConfig, peer string) (*Desync, error) {
	if err := validateDesync(cfg); err != nil {
		return nil, err
	}
	ipStr, _ := desyncPeerHostPort(peer)
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("wat: desync needs an IPv4 -peer")
	}
	var p [4]byte
	copy(p[:], ip.To4())
	inj, err := newDesyncInjector(cfg, p)
	if err != nil {
		return nil, err
	}
	return &Desync{inj: inj}, nil
}

// Wrap announces the connection to the sniffer, waits for the fake to fire, and returns the connection unchanged.
// A connection that is not a plain IPv4 TCP connection passes through unwrapped; a handshake the sniffer never
// sees (offload paths) passes through after 2 s.
func (d *Desync) Wrap(c net.Conn) (net.Conn, error) {
	// the tls/wss/h2 carriers hand their hook an already-handshaked *tls.Conn (or a WS/HTTP framing wrapper);
	// unwrap to the socket underneath, like newPoolConn does (rawTCP)
	tc := rawTCP(c)
	if tc == nil {
		return c, nil
	}
	la, ok := tc.LocalAddr().(*net.TCPAddr)
	ra, ok2 := tc.RemoteAddr().(*net.TCPAddr)
	if !ok || !ok2 || la.IP.To4() == nil || ra.IP.To4() == nil {
		return c, nil
	}
	var s, r [4]byte
	copy(s[:], la.IP.To4())
	copy(r[:], ra.IP.To4())
	k := desyncKey{s, r, uint16(la.Port), uint16(ra.Port)}
	// The probe reports SND.NXT = the next unsent sequence number. The tracker's announce stores the ISN (the
	// stream start minus one): the early fire compares segment seq against synSeq+1, and the NAT follow rebuilds
	// synSeq from a SYN-ACK's ack the same way. Handshake just finished => SND.NXT = ISN+1 => ISN = SND.NXT-1.
	isn, known := tcpStreamBase(tc)
	if known {
		isn--
	}
	ch := d.inj.tr.announce(k, isn, known)
	if known {
		select {
		case <-ch: // fake fired on final ACK
		case <-time.After(desyncWrapTimeout): // never observed: connect anyway, the tunnel still works
			d.inj.tr.abandon(k)
		}
	}
	return c, nil
}

// Close stops the sniffer.
func (d *Desync) Close() error { d.inj.close(); return nil }

// ---------------------------------------------------------------- injector

// desyncInjector is one sniffer for the pool of one client process, over the portable tracker.
type desyncInjector struct {
	tr     *desyncTracker
	fd     int
	closed sync.Once
}

// newDesyncInjector starts the sniffer. peerIP is the pool's server IP.
func newDesyncInjector(cfg DesyncConfig, peerIP [4]byte) (*desyncInjector, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("wat: -fake-sni needs CAP_NET_RAW: %w", err)
	}
	d := &desyncInjector{fd: fd, tr: newDesyncTracker(cfg, peerIP)}
	d.tr.send = d.sendRaw
	go d.loop()
	return d, nil
}

func (d *desyncInjector) close() {
	d.closed.Do(func() {
		d.tr.close()
		unix.Close(d.fd)
	})
}

// loop reads ethernet frames and feeds them to the tracker.
func (d *desyncInjector) loop() {
	// 64 KB: AF_PACKET delivers one frame per read, and TSO/GRO can hand the tap multi-KB
	// super-frames; a 2048-byte read silently truncated them and the fake trigger was missed
	// intermittently (audit 2026-10-22).
	buf := make([]byte, 65536)
	pfd := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
	for {
		// Poll with 200 ms timeout so the goroutine sleeps in the kernel when idle instead of spinning on EAGAIN.
		nReady, err := unix.Poll(pfd, 200)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if nReady == 0 {
			continue
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return
		}
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		if ip := parseEthIPv4(buf[:n]); ip != nil {
			d.tr.handleIPv4(ip)
		}
	}
}

// sendRaw writes one crafted IPv4 packet through a raw IP socket (IP_HDRINCL, the kernel fills the checksum).
// One socket per fire: a fire happens once per pool connection, orders of magnitude too rare to matter.
func (d *desyncInjector) sendRaw(pkt []byte) {
	sendRawPacket(pkt)
}

// sendRawPacket is the raw injector every fire path shares (the tracker's send seam and the startup probe).
func sendRawPacket(pkt []byte) {
	if len(pkt) < 24 {
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	src := pkt[12:16]
	if src[0] != 0 || src[1] != 0 || src[2] != 0 || src[3] != 0 {
		_ = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{src[0], src[1], src[2], src[3]}})
	}
	dst := pkt[16:20]
	_ = unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Port: int(binary.BigEndian.Uint16(pkt[22:])), Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}})
}
