package wat

import (
	"crypto/sha256"
	"math/rand/v2"
	"time"

	"golang.org/x/crypto/chacha20"
)

// Traffic shape (3.0.0). A session packet starts with its session id (constant for the whole session) and an explicit
// packet number (a counter) in clear, so a flow classifier sees 8 equal bytes in every datagram plus an increasing
// number behind them, whatever the carrier. maskHdr hides both: it XORs the 16 header bytes with a ChaCha20 keystream
// keyed from the PSK and seeded by the first 12 ciphertext bytes (like QUIC header protection), so every packet
// header looks random and differs from the last. The receiver cannot read the session id before unmasking, so the
// key is per PSK, not per session. Old peers send and expect the plain header: a receiver tries the plain header
// first (a known session id) and the masked one second, answers in the form it was addressed in, and a client that
// hears nothing flips between the two forms every few seconds until a packet authenticates (Session.timers).
//
// Padding and ping jitter change only sizes and timing: frPad is an ignorable frame placed last in packets that carry
// no stream data, and the idle keepalive interval is re-rolled around Config.PingEvery after every ping.

// hdrMaskKey derives the header-mask key from the PSK.
func hdrMaskKey(psk []byte) []byte {
	h := sha256.Sum256(append([]byte("wattun header mask v1\x00"), psk...))
	return h[:]
}

// hdrKeystream is the mask for pkt's header, seeded by the 12 bytes after it.
func hdrKeystream(key, pkt []byte) (ks [hdrLen]byte, ok bool) {
	if len(pkt) < hdrLen+12 {
		return ks, false
	}
	c, err := chacha20.NewUnauthenticatedCipher(key, pkt[hdrLen:hdrLen+12])
	if err != nil {
		return ks, false
	}
	c.XORKeyStream(ks[:], ks[:])
	return ks, true
}

// maskHdr masks or unmasks (the same operation) the first hdrLen bytes of a sealed packet in place.
func maskHdr(key, pkt []byte) {
	if ks, ok := hdrKeystream(key, pkt); ok {
		for i := range ks {
			pkt[i] ^= ks[i]
		}
	}
}

// unmaskedHdr returns the header pkt would have if it were masked, leaving pkt alone (the server's demux reads the
// session id this way and hands the packet on untouched, for the session to unmask).
func unmaskedHdr(key, pkt []byte) (h [hdrLen]byte) {
	copy(h[:], pkt)
	if ks, ok := hdrKeystream(key, pkt); ok {
		for i := range ks {
			h[i] ^= ks[i]
		}
	}
	return h
}

const (
	padBelow = 192 // pad packets whose plaintext is shorter than this (acks, pings, key exchange)
	padMax   = 100 // at most this many pad bytes (a one-byte length), so an idle exchange spreads over ~100 sizes
)

// padCapMask is the first byte of a padding frame from a peer that reads masked headers (older peers skip padding
// whatever it holds). A client that took the plain form because nothing answered, for instance because the server
// started later, then moves to the masked form instead of staying plain for the whole session.
const padCapMask = 1

var zeroPad [padMax]byte

// pad appends a frPad frame of random length to a packet that carries no stream data. It stays inside maxPlain.
func (s *Session) pad(p []byte) []byte {
	if len(p) >= padBelow {
		return p
	}
	room := min(padMax, s.maxPlain-len(p)-2)
	if room < 1 {
		return p
	}
	n := 1 // NoShape: only the capability byte
	if !s.cfg.NoShape {
		n = 1 + rand.IntN(room)
	}
	p = append(p, frPad, byte(n))
	if s.hk != nil {
		p = append(p, padCapMask)
		n--
	}
	return append(p, zeroPad[:n]...)
}

// nextPingGap rolls the idle keepalive interval to 60-140 % of Config.PingEvery.
func (s *Session) nextPingGap() time.Duration {
	if s.cfg.NoShape {
		return s.cfg.PingEvery
	}
	return time.Duration(float64(s.cfg.PingEvery) * (0.6 + 0.8*rand.Float64()))
}
