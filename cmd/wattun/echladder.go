package main

// ECH bootstrap ladder (2.9.0): -ech ladder fetches the ECH config of the SNI name through the tunnel's own
// DoH relay when the direct DoH servers are unreachable (Iran: 1.1.1.1 & co are IP-blocked).
//
// Wire contract, the same trick as the speed test's target 0 (never a real local port): a stream whose 2-byte
// target header is 53 goes to the server's built-in DNS relay instead of a local service. The client writes
// one raw DNS query (the exact wire format of buildDNSQuery, echoed by the speed-test pattern of "op bytes
// after the header"), the relay forwards it over UDP/TCP to a recursive resolver on the Kharej side and
// writes the answer back. Old servers (2.5.0) dial 127.0.0.1:53, fail, reset the stream: the ladder falls
// back to "no ECH", exactly the behaviour it had. New server + old client: unused. Both ends still interop.
//
// The ladder in full: direct DoH (the raced public servers) -> the tunnel relay (port 53) -> no ECH, retry
// later. Only -ech ladder enables the second step; -ech auto keeps its old behaviour exactly.

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

// dnsRelayPort is the reserved server target port for the built-in DNS relay (like speedTestPort 0).
const dnsRelayPort = 53

// dnsRelayTimeout bounds one relayed query (var: tests point it at a stub upstream).
var dnsRelayTimeout = 6 * time.Second

// dnsRelayUpstream is the recursive resolver the relay asks on the Kharej side (UDP, plain DNS).
var dnsRelayUpstream = "8.8.8.8:53"

// maxDNSMsgLen bounds DNS queries and answers to 4096 bytes (RFC 6891 EDNS0 maximum).
const maxDNSMsgLen = 4096

// serveDNSRelay runs on the server for a stream whose header asked for port 53. One query per stream, the
// same one-shot shape as serveSpeedTest. No allowlist check: like target 0, it is built-in, never a local
// service, and a DNS query carries no more information than the tunnel's own handshake already does.
func serveDNSRelay(st *wat.Stream) {
	defer st.CloseWrite()
	var q [2]byte // the port header was already read by serve(); read the query length next
	if _, err := io.ReadFull(st, q[:]); err != nil {
		return
	}
	qlen := int(q[0])<<8 | int(q[1])
	if qlen < 12 || qlen > maxDNSMsgLen { // a DNS query is 12..4096 bytes (RFC 6891 EDNS0); bigger is abuse
		return
	}
	query := make([]byte, qlen)
	if _, err := io.ReadFull(st, query); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsRelayTimeout)
	defer cancel()
	var d net.Dialer
	pc, err := d.DialContext(ctx, "udp", dnsRelayUpstream)
	if err != nil {
		return
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(dnsRelayTimeout))
	if _, err := pc.Write(query); err != nil {
		return
	}
	buf := make([]byte, 4096)
	n, err := pc.Read(buf) // one response, like every stub resolver's UDP exchange
	if err != nil || n == 0 {
		return
	}
	if n >= 12 && buf[2]&0x02 != 0 {
		// Upstream indicated truncation (TC=1): query upstream over TCP for the full untruncated answer
		if tcpConn, err := d.DialContext(ctx, "tcp", dnsRelayUpstream); err == nil {
			defer tcpConn.Close()
			_ = tcpConn.SetDeadline(time.Now().Add(dnsRelayTimeout))
			qlenHdr := [2]byte{byte(len(query) >> 8), byte(len(query))}
			if _, err := tcpConn.Write(qlenHdr[:]); err == nil {
				if _, err := tcpConn.Write(query); err == nil {
					var rlenHdr [2]byte
					if _, err := io.ReadFull(tcpConn, rlenHdr[:]); err == nil {
						tn := int(rlenHdr[0])<<8 | int(rlenHdr[1])
						if tn >= 12 && tn <= 4096 {
							tbuf := make([]byte, tn)
							if _, err := io.ReadFull(tcpConn, tbuf); err == nil {
								buf, n = tbuf, tn
							}
						}
					}
				}
			}
		}
	}
	alen := [2]byte{byte(n >> 8), byte(n)}
	if _, err := st.Write(alen[:]); err != nil {
		return
	}
	_, _ = st.Write(buf[:n])
}

// dialDNSRelay asks the tunnel's relay one query (client side). tun may be nil (called before the sessions
// exist): the caller treats an error as "ladder step failed", never as fatal.
func dialDNSRelay(tun *tunnel, query []byte) ([]byte, error) {
	if tun == nil {
		return nil, errors.New("no tunnel yet")
	}
	sess := tun.pick()
	if sess == nil || !sess.Alive() {
		return nil, errors.New("tunnel down")
	}
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	defer st.Reset()
	// Stream has no deadline support; the exchange runs in a goroutine and the timeout abandons it
	// (Reset ends the stream, so nothing leaks on either side).
	type res struct {
		ans []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		hdr := [2]byte{byte(dnsRelayPort >> 8), byte(dnsRelayPort)}
		if _, err := st.Write(hdr[:]); err != nil {
			ch <- res{nil, err}
			return
		}
		qlen := [2]byte{byte(len(query) >> 8), byte(len(query))}
		if _, err := st.Write(qlen[:]); err != nil {
			ch <- res{nil, err}
			return
		}
		if _, err := st.Write(query); err != nil {
			ch <- res{nil, err}
			return
		}
		var alen [2]byte
		if _, err := io.ReadFull(st, alen[:]); err != nil {
			ch <- res{nil, err}
			return
		}
		n := int(alen[0])<<8 | int(alen[1])
		if n == 0 || n > 4096 {
			ch <- res{nil, errors.New("bad relay answer")}
			return
		}
		ans := make([]byte, n)
		if _, err := io.ReadFull(st, ans); err != nil {
			ch <- res{nil, err}
			return
		}
		ch <- res{ans, nil}
	}()
	select {
	case r := <-ch:
		return r.ans, r.err
	case <-time.After(dnsRelayTimeout):
		return nil, errors.New("relay timed out")
	}
}
