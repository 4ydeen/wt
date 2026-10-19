package wat

// Fake-SNI desync (client side, Linux only, desync_linux.go): after the kernel finishes the TCP handshake, a raw
// packet carrying a fake TLS ClientHello with an allowlisted SNI is injected next to the real flow. The DPI reads
// it and marks the flow as TLS to an allowlisted site; the server never accepts it (out-of-window seq, or a TTL
// that expires at the censor's hop), so the relay then carries the session's own encrypted datagrams, which the
// DPI now passes as TLS application data. Server-side changes: none. Reverse-engineered from tools that kept
// working through the 2026 whitelisting (patterniha/SNI-Spoofing's wrong-seq method; see docs/TECHNICAL.md).
//
// This file holds the OS-independent parts so they are testable everywhere.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
)

// htons swaps byte order for the socket option calls that take a network-order constant.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// csum is the internet checksum (also used by the ICMP carrier, icmp_linux.go).
func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// tcpChecksum computes the TCP checksum over the pseudo header, TCP header and payload.
func tcpChecksum(th, src, dst []byte) uint16 {
	ph := make([]byte, 12)
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = 6 // TCP
	binary.BigEndian.PutUint16(ph[10:], uint16(len(th)))
	return csum(append(ph, th...))
}

// DesyncConfig tunes the fake-SNI layer of the tcp and tls carriers.
type DesyncConfig struct {
	SNI  string // allowlisted server name the fake ClientHello carries
	Mode string // "seq" (wrong sequence number, default) or "ttl" (small TTL, packet dies at the DPI hop)
	TTL  int    // ttl mode: hop count of the fake packet (required for ttl mode; seq mode ignores it)
}

// FakeClientHello builds a minimal TLS 1.2-format ClientHello carrying sni. The censor only parses it for the
// SNI; our own server never sees it, so there is no fingerprint to match and no handshake to complete.
func FakeClientHello(sni string) []byte {
	if sni == "" {
		return nil
	}
	sniB := []byte(sni)
	// server_name extension, standard layout: 0000 | ext_len | list_len | 00 (host name) | name_len | name
	ext := []byte{0, 0, byte((len(sniB) + 5) >> 8), byte(len(sniB) + 5), byte((len(sniB) + 3) >> 8), byte(len(sniB) + 3),
		0, byte(len(sniB) >> 8), byte(len(sniB))}
	ext = append(ext, sniB...)
	// supported_groups (secp256r1) and signature_algorithms (ecdsa_secp256r1_sha256): a TLS 1.2 ECDHE-ECDSA
	// handshake needs both, and a real parser checks them before the cipher choice.
	ext = append(ext, 0, 0x0a, 0, 6, 0, 4, 0, 0x17, 0, 0x18)  // groups: x25519, secp256r1
	ext = append(ext, 0, 0x0d, 0, 4, 0, 2, 0x04, 0x03)        // sigalgs: ecdsa_secp256r1_sha256

	body := make([]byte, 0, 64+len(ext))
	body = append(body, 0x03, 0x03) // client version 1.2 in the clear, like every real ClientHello
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)
	body = append(body, 0)                                 // session id length 0
	body = append(body, 0, 4, 0xc0, 0x2b, 0xc0, 0x23)      // ECDHE-ECDSA-AES128-GCM-SHA256 / -AES128-SHA256
	body = append(body, 1, 0)                              // compression: null
	body = append(body, byte(len(ext)>>8), byte(len(ext))) // extensions length
	body = append(body, ext...)

	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

// parseSNIOf returns the SNI a ClientHello built by FakeClientHello carries (test helper).
func parseSNIOf(rec []byte) (string, error) {
	if len(rec) < 5 || rec[0] != 0x16 {
		return "", fmt.Errorf("not a handshake record")
	}
	l := int(rec[3])<<8 | int(rec[4])
	if len(rec) < 5+l {
		return "", fmt.Errorf("short record")
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 {
		return "", fmt.Errorf("not a clienthello")
	}
	p := 4 + 2 + 32 // handshake header + client version + client random
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // skip session id
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	cs := int(hs[p])<<8 | int(hs[p+1])
	p += 2 + cs
	if len(hs) < p+1 {
		return "", fmt.Errorf("truncated")
	}
	p += 1 + int(hs[p]) // compression methods
	if len(hs) < p+2 {
		return "", fmt.Errorf("truncated")
	}
	el := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	for off := 0; off+4 <= el && p+off+4 <= len(hs); {
		typ := int(hs[p+off])<<8 | int(hs[p+off+1])
		szl := int(hs[p+off+2])<<8 | int(hs[p+off+3])
		if typ == 0 { // server_name: list_len(2) | 00 (host name type) | name_len(2) | name
			q := p + off + 4
			if q+5 > len(hs) {
				break
			}
			nl := int(hs[q+3])<<8 | int(hs[q+4])
			if q+5+nl > len(hs) {
				break
			}
			return string(hs[q+5 : q+5+nl]), nil
		}
		off += 4 + szl
	}
	return "", fmt.Errorf("no sni")
}

// desyncPeerIP extracts the IP of a host:port peer (empty when unresolvable).
func desyncPeerIP(peer string) string {
	h, _, err := net.SplitHostPort(peer)
	if err != nil {
		h = peer
	}
	if ip := net.ParseIP(h); ip != nil {
		return h
	}
	if addrs, err := net.LookupHost(h); err == nil && len(addrs) > 0 {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				return a
			}
		}
		return addrs[0]
	}
	return ""
}
