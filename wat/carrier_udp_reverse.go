package wat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Reverse udp (3.0.0): the Iran client binds a UDP port and never sends first; the Kharej server sends it small
// "punch" datagrams from its own socket, and the client answers to whatever address the latest valid punch came from.
// A flow from Iran's point of view is then started by the foreign host, like an inbound TCP connection (the model of
// Backhaul-style reverse tunnels), so a filter that restricts what an Iran VPS may START towards foreign addresses
// never sees a new outbound flow. A punch is nonce(8) + HMAC(12) + 0-40 random bytes: no constant byte, and no
// session packet (33+ bytes, its first 20 bytes random) is mistaken for one except by a 2^-96 chance.

const (
	punchCore  = 20
	punchEvery = time.Second
)

func punchKey(psk []byte) []byte {
	h := sha256.Sum256(append([]byte("wattun punch v1\x00"), psk...))
	return h[:]
}

func makePunch(key []byte) []byte {
	b := make([]byte, punchCore+mrand.IntN(41))
	rand.Read(b)
	m := hmac.New(sha256.New, key)
	m.Write(b[:8])
	copy(b[8:punchCore], m.Sum(nil))
	return b
}

func isPunch(key, p []byte) bool {
	if len(p) < punchCore || len(p) > punchCore+40 {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(p[:8])
	return hmac.Equal(p[8:punchCore], m.Sum(nil)[:punchCore-8])
}

// UDPReverseListener is the client PacketIO of a reverse udp tunnel.
type UDPReverseListener struct {
	c    *net.UDPConn
	key  []byte
	peer atomic.Pointer[net.UDPAddr] // where the last valid punch came from (nil: none yet, so Send drops)
	rbuf []byte
	bx   *udpBatch
	dns  bool // DNS-shaped datagrams (dnsshape.go)
}

// SetDNS turns the DNS framing on or off; call it before the first Recv. Both ends must agree.
func (u *UDPReverseListener) SetDNS(on bool) { u.dns = on }

// NewUDPReverseListener binds addr (":4443") and waits for the server's punches.
func NewUDPReverseListener(addr string, psk []byte) (*UDPReverseListener, error) {
	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	c.SetReadBuffer(udpSockBuf)
	c.SetWriteBuffer(udpSockBuf)
	return &UDPReverseListener{c: c, key: punchKey(psk), rbuf: make([]byte, 65536), bx: newUDPBatch(c)}, nil
}

func (u *UDPReverseListener) Send(p []byte, path int) error {
	dst := u.peer.Load()
	if dst == nil {
		return nil // nobody has punched yet: loss the session repairs once the server shows up
	}
	if u.dns {
		fs, done := dnsFrames([][]byte{p}, false)
		defer done()
		p = fs[0]
	}
	_, err := u.c.WriteToUDP(p, dst)
	return err
}

func (u *UDPReverseListener) Recv() ([]byte, int, net.Addr, error) {
	for {
		var p []byte
		var src net.Addr
		if u.bx != nil {
			var err error
			if p, src, err = u.bx.recv(); err != nil {
				return nil, 0, nil, err
			}
		} else {
			n, a, err := u.c.ReadFromUDPAddrPort(u.rbuf)
			if err != nil {
				return nil, 0, nil, err
			}
			p, src = u.rbuf[:n], net.UDPAddrFromAddrPort(a)
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		if u.dns {
			if p = dnsStrip(p); p == nil {
				continue
			}
		}
		if isPunch(u.key, p) {
			if cur := u.peer.Load(); cur == nil || !cur.IP.Equal(ua.IP) || cur.Port != ua.Port {
				u.peer.Store(ua)
			}
			continue
		}
		if cur := u.peer.Load(); cur == nil || !cur.IP.Equal(ua.IP) || cur.Port != ua.Port {
			continue // not from the punching server: the session would reject it anyway
		}
		return p, 0, ua, nil
	}
}

func (u *UDPReverseListener) CopiesOnSend() bool { return true }
func (u *UDPReverseListener) SetPeer(net.Addr)   {}
func (u *UDPReverseListener) Profile() Profile   { return udpProfile }
func (u *UDPReverseListener) Close() error       { return u.c.Close() }

// Addr is the bound address (useful with port 0).
func (u *UDPReverseListener) Addr() net.Addr { return u.c.LocalAddr() }

// UDPReverseServer is the server RawIO of a reverse udp tunnel: a normal UDPServer that also punches towards the
// client's address until the tunnel is closed.
type UDPReverseServer struct {
	*UDPServer
	stop chan struct{}
	once sync.Once
}

// SetDNS frames the punches too, so call it right after NewUDPReverseServer (a punch sent before it is unframed and
// the listener ignores it; the next one, about a second later, is framed).
func (r *UDPReverseServer) SetDNS(on bool) { r.UDPServer.SetDNS(on) }

// NewUDPReverseServer binds listen (the source port of the punches and of every reply) and punches to peer.
func NewUDPReverseServer(listen, peer string, psk []byte) (*UDPReverseServer, error) {
	us, err := NewUDPServer(listen)
	if err != nil {
		return nil, err
	}
	r := &UDPReverseServer{UDPServer: us, stop: make(chan struct{})}
	key := punchKey(psk)
	go func() {
		for {
			if ra, err := net.ResolveUDPAddr("udp", peer); err == nil {
				pk := makePunch(key)
				if us.dns.Load() {
					pk = dnsFrame(nil, pk, true)
				}
				us.c.WriteToUDP(pk, ra)
			}
			select {
			case <-r.stop:
				return
			case <-time.After(time.Duration(float64(punchEvery) * (0.6 + 0.8*mrand.Float64()))):
			}
		}
	}()
	return r, nil
}

func (r *UDPReverseServer) Close() error {
	r.once.Do(func() { close(r.stop) })
	return r.UDPServer.Close()
}
