package wat

import (
	mrand "math/rand/v2"
	"sync"
)

// DNS-shaped udp (3.0.0): with Config-level `udp-dns` every datagram of the udp carrier starts with a DNS message
// header and one question, and the session packet follows as if it were the rest of the message. It exists for
// routes that cut a UDP flow after its first datagrams unless it looks like an allowed protocol: measured on a fresh
// Iran/Kharej pair (2026-10-25), UDP to port 53 passes sustained 1400-byte datagrams in both directions when the first
// bytes are a valid DNS header and question, while the same bytes as random data are cut after three datagrams on every
// port. Run it on port 53 (or any port) of the server; both ends must enable it, an older peer cannot read the frame.
//
// Frame: id(2, random) flags(2) qdcount=1 ancount=0 nscount=0 arcount=0, then one question (a random 5-14 character
// label plus a top-level label, type A or AAAA, class IN), then the payload. Client frames look like recursive
// queries (flags 0x0100), server frames like empty NOERROR answers (0x8180). Nothing in it is constant except the
// shape of a DNS message; the id and the name are fresh for every datagram. Cost: 26 to 37 bytes per datagram.

const (
	dnsHdr      = 12
	dnsMaxFrame = dnsHdr + 1 + 14 + 1 + 4 + 1 + 4 // header + longest question
	dnsQuery    = 0x0100
	dnsAnswer   = 0x8180
)

var dnsTLD = [...]string{"com", "net", "org", "ir", "info", "io"}

const dnsAlpha = "abcdefghijklmnopqrstuvwxyz0123456789"

// dnsFrame appends the DNS prefix and payload to dst. resp selects the server-side (answer) flags.
func dnsFrame(dst, payload []byte, resp bool) []byte {
	r := mrand.Uint64()
	flags := uint16(dnsQuery)
	if resp {
		flags = dnsAnswer
	}
	dst = append(dst, byte(r), byte(r>>8), byte(flags>>8), byte(flags), 0, 1, 0, 0, 0, 0, 0, 0)
	n := 5 + int(r>>16)%10
	dst = append(dst, byte(n))
	for i := 0; i < n; i++ {
		r = r*6364136223846793005 + 1442695040888963407
		dst = append(dst, dnsAlpha[int(r>>33)%len(dnsAlpha)])
	}
	tld := dnsTLD[int(r>>20)%len(dnsTLD)]
	dst = append(dst, byte(len(tld)))
	dst = append(dst, tld...)
	qt := byte(1) // A
	if r>>40&3 == 0 {
		qt = 28 // AAAA
	}
	dst = append(dst, 0, 0, qt, 0, 1)
	return append(dst, payload...)
}

// dnsStrip returns the payload of a frame made by dnsFrame, or nil when p is not one.
func dnsStrip(p []byte) []byte {
	if len(p) < dnsHdr+1 || p[4] != 0 || p[5] != 1 {
		return nil
	}
	i := dnsHdr
	for labels := 0; labels < 4; labels++ {
		l := int(p[i])
		if l == 0 {
			i += 1 + 4
			if i >= len(p) {
				return nil
			}
			return p[i:]
		}
		if l > 63 {
			return nil
		}
		i += 1 + l
		if i >= len(p) {
			return nil
		}
	}
	return nil
}

var dnsBufs = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// dnsFrames frames every packet of ps into one pooled buffer; call done when the send has returned.
func dnsFrames(ps [][]byte, resp bool) (out [][]byte, done func()) {
	bp := dnsBufs.Get().(*[]byte)
	need := 0
	for _, p := range ps {
		need += len(p) + dnsMaxFrame
	}
	if cap(*bp) < need {
		*bp = make([]byte, 0, need)
	}
	buf := (*bp)[:0]
	out = make([][]byte, len(ps))
	for i, p := range ps {
		s := len(buf)
		buf = dnsFrame(buf, p, resp)
		out[i] = buf[s:len(buf):len(buf)]
	}
	return out, func() { *bp = buf[:0]; dnsBufs.Put(bp) }
}
