//go:build linux

package wat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Raw injection of the fake ClientHello (see desync.go). The kernel does not export a socket's ISN, so a small
// AF_PACKET sniffer watches the pool's own outgoing SYNs and the server's SYN-ACKs, exactly the state machine of
// the tool this method is reverse-engineered from: on the final ACK of the handshake a fake ClientHello is
// injected whose seq is payload bytes below ISN+1. The server sees an old duplicate, dup-ACKs it away; a DPI
// that reassembles the flow without window checks reads the allowlisted SNI and passes the flow. ttl mode sends
// the same fake with a TTL that dies at the censor's hop instead. Requires CAP_NET_RAW, like the ICMP carrier.

// Desync is the fake-SNI injector of one client process: created once with NewDesync, every pool connection
// passes through Wrap after the kernel handshake.
type Desync struct {
	inj *desyncInjector
}

// NewDesync starts the sniffer for the peer (host:port or IP). Linux only; needs CAP_NET_RAW.
func NewDesync(cfg DesyncConfig, peer string) (*Desync, error) {
	if cfg.SNI == "" {
		return nil, errors.New("wat: desync: empty SNI")
	}
	switch cfg.Mode {
	case "", "seq", "ttl":
	default:
		return nil, fmt.Errorf("wat: -fake-mode must be seq or ttl, got %q", cfg.Mode)
	}
	if cfg.Mode == "ttl" && cfg.TTL <= 0 {
		return nil, errors.New("wat: -fake-mode ttl needs -fake-ttl (hop count that dies at the censor, not the server)")
	}
	ip := desyncPeerIP(peer)
	if ip == "" {
		return nil, errors.New("wat: desync cannot resolve the peer")
	}
	inj, err := newDesyncInjector(cfg, ip)
	if err != nil {
		return nil, err
	}
	return &Desync{inj: inj}, nil
}

// Wrap waits for the connection's handshake to complete (the injector watches the raw packets), then returns the
// connection; the fake has been sent by then. A connection that is not a plain IPv4 TCP connection passes through
// unwrapped; a handshake the sniffer never sees (offload paths) passes through after 2 s.
func (d *Desync) Wrap(c net.Conn) (net.Conn, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
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
	ch := d.inj.announce(s, r, uint16(la.Port), uint16(ra.Port))
	select {
	case <-ch: // fake fired
	case <-time.After(2 * time.Second): // never observed: connect anyway, the tunnel still works, just unclassified
	}
	return c, nil
}

// Close stops the sniffer.
func (d *Desync) Close() error { d.inj.close(); return nil }

// desyncInjector is one sniffer + raw socket for the pool of one client process.
type desyncInjector struct {
	mu     sync.Mutex
	conns  map[desyncKey]*desyncConn
	wait   map[desyncKey]chan struct{} // closed by fire(), waited on by Wrap
	fd     int
	cfg    DesyncConfig
	closed bool
}

type desyncKey struct {
	srcIP [4]byte
	dstIP [4]byte
	srcPt uint16
	dstPt uint16
}

type desyncConn struct {
	synSeq    uint32 // the ISN of our outgoing SYN
	synAckSeq uint32 // seq of the server's SYN-ACK
	synAckAck uint32 // ack field of the server's SYN-ACK (== ISN+1)
	done      bool
}

// newDesyncInjector starts the sniffer. peerIP is the pool's server IP.
func newDesyncInjector(cfg DesyncConfig, peerIP string) (*desyncInjector, error) {
	ip := net.ParseIP(peerIP)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("wat: desync needs an IPv4 -peer")
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("wat: -fake-sni needs CAP_NET_RAW: %w", err)
	}
	d := &desyncInjector{conns: map[desyncKey]*desyncConn{}, wait: map[desyncKey]chan struct{}{}, fd: fd, cfg: cfg}
	go d.loop()
	return d, nil
}

// announce registers a connection Wrap is waiting for (the outgoing 4-tuple) and returns its channel.
func (d *desyncInjector) announce(srcIP [4]byte, dstIP [4]byte, srcPt, dstPt uint16) chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	ch := make(chan struct{})
	d.wait[desyncKey{srcIP, dstIP, srcPt, dstPt}] = ch
	return ch
}

func (d *desyncInjector) close() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	unix.Close(d.fd)
}

// loop reads packets, tracks handshakes of announced connections and fires the fake.
func (d *desyncInjector) loop() {
	buf := make([]byte, 2048)
	for {
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			if d.closed {
				return
			}
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			time.Sleep(10 * time.Millisecond) // unexpected: back off, Wrap's timeout governs
			continue
		}
		d.handle(buf[:n])
	}
}

// handle parses one ethernet frame and advances one connection's state machine. Announced keys are the OUTGOING
// 4-tuple (src = us); an inbound frame matches the reversed key, the inbound/outbound split of the tool this is
// modelled on.
func (d *desyncInjector) handle(frame []byte) {
	if len(frame) < 14+20+20 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:]) != 0x0800 { // IPv4 only, like the tool
		return
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 || ip[9] != unix.IPPROTO_TCP {
		return
	}
	ihl := int(ip[0]&0xf) * 4
	th := ip[ihl:]
	srcIP := [4]byte{ip[12], ip[13], ip[14], ip[15]}
	dstIP := [4]byte{ip[16], ip[17], ip[18], ip[19]}
	out := desyncKey{srcIP, dstIP, binary.BigEndian.Uint16(th[0:]), binary.BigEndian.Uint16(th[2:])}
	in := desyncKey{dstIP, srcIP, binary.BigEndian.Uint16(th[2:]), binary.BigEndian.Uint16(th[0:])}
	syn := th[13]&0x02 != 0
	ack := th[13]&0x10 != 0
	payload := len(ip) - ihl - int(th[12]>>4)*4

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	// our outgoing SYN: remember the ISN and start tracking
	if syn && !ack && payload == 0 {
		if _, ok := d.conns[out]; !ok {
			if _, ok := d.wait[out]; ok {
				d.conns[out] = &desyncConn{synSeq: binary.BigEndian.Uint32(th[4:])}
			}
		}
		return
	}
	// inbound SYN-ACK for a tracked conn: remember its seq and ack (our ISN+1)
	if syn && ack && payload == 0 {
		if c := d.conns[in]; c != nil && !c.done {
			c.synAckSeq = binary.BigEndian.Uint32(th[4:])
			c.synAckAck = binary.BigEndian.Uint32(th[8:])
		}
		return
	}
	// our outgoing final ACK of the handshake: fire the fake next to it
	if ack && !syn && payload == 0 {
		c := d.conns[out]
		if c == nil || c.done || c.synAckAck == 0 {
			return
		}
		if binary.BigEndian.Uint32(th[8:]) != c.synAckSeq+1 { // not acking the SYN-ACK: not the final ACK
			return
		}
		c.done = true
		if ch := d.wait[out]; ch != nil {
			delete(d.wait, out)
			close(ch)
		}
		go d.fire(out, c)
	}
}

// fire builds and sends the fake packet for one completed handshake.
func (d *desyncInjector) fire(k desyncKey, c *desyncConn) {
	hello := FakeClientHello(d.cfg.SNI)
	if hello == nil {
		return
	}
	ttl := 64
	if d.cfg.Mode == "ttl" {
		ttl = d.cfg.TTL // validated > 0 by NewDesync
	}
	// seq = ISN + 1 - len(fake): the fake lands exactly below the stream start. The server holds snd_una at
	// ISN+1, so this is an old duplicate; a DPI without window checks reassembles it as the first flight.
	seq := c.synSeq + 1 - uint32(len(hello))
	pkt := make([]byte, 20+20+len(hello))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[6] = 0x40 // Don't Fragment
	pkt[8] = byte(ttl)
	pkt[9] = unix.IPPROTO_TCP
	copy(pkt[12:16], k.srcIP[:])
	copy(pkt[16:20], k.dstIP[:])
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:], k.srcPt)
	binary.BigEndian.PutUint16(th[2:], k.dstPt)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], c.synAckAck) // ack the server's SYN so it parses the segment
	th[12] = 0x50
	th[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	copy(th[20:], hello)
	binary.BigEndian.PutUint16(th[16:], tcpChecksum(pkt[20:], k.srcIP[:], k.dstIP[:]))
	d.sendRaw(pkt)
}

// sendRaw writes one crafted IPv4 packet through a raw IP socket (IP_HDRINCL, the kernel fills the checksum).
func (d *desyncInjector) sendRaw(pkt []byte) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	dst := pkt[16:20]
	_ = unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Port: int(binary.BigEndian.Uint16(pkt[22:])), Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}})
}
