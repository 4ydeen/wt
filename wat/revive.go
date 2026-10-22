package wat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ReviveMagic            uint32 = 0x57524556 // "WREV"
	ReviveReloadListeners  uint8  = 0x01
	ReviveReverseCompanion uint8  = 0x02
	ReviveFlushRateLimits  uint8  = 0x03
	ReviveMaxSkew                 = 60 * time.Second
	reviveRingSize                = 2048
)

var b32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// ReviveEngine handles cryptographic construction, authentication, replay protection,
// and execution of low-rate out-of-band emergency revival signals.
type ReviveEngine struct {
	key      []byte
	mu       sync.Mutex
	seenRing [reviveRingSize][16]byte
	seenIdx  int
	onRevive func(action uint8, src net.Addr)
}

// NewReviveEngine initializes a revive engine with keys derived from PSK.
func NewReviveEngine(psk []byte, onRevive func(uint8, net.Addr)) *ReviveEngine {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("wat-revive-auth"))
	derived := h.Sum(nil)
	return &ReviveEngine{
		key:      derived,
		onRevive: onRevive,
	}
}

// BuildKnock creates a 36-byte authenticated knock packet.
func (e *ReviveEngine) BuildKnock(action uint8) ([]byte, error) {
	buf := make([]byte, 36)
	binary.BigEndian.PutUint32(buf[0:4], ReviveMagic)
	buf[4] = action
	buf[5] = 0 // reserved
	now := time.Now().Unix()
	binary.BigEndian.PutUint64(buf[6:14], uint64(now))
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(buf[14:22], nonce[:])

	mac := hmac.New(sha256.New, e.key)
	mac.Write(buf[0:22])
	tag := mac.Sum(nil)
	copy(buf[22:36], tag[:14])
	return buf, nil
}

// VerifyKnock authenticates a raw 36-byte knock, checks freshness and replay,
// and invokes onRevive if valid.
func (e *ReviveEngine) VerifyKnock(p []byte, src net.Addr) (uint8, error) {
	if len(p) < 36 {
		return 0, errors.New("revive: short packet")
	}
	if binary.BigEndian.Uint32(p[0:4]) != ReviveMagic {
		return 0, errors.New("revive: bad magic")
	}
	action := p[4]
	ts := int64(binary.BigEndian.Uint64(p[6:14]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < -int64(ReviveMaxSkew/time.Second) || diff > int64(ReviveMaxSkew/time.Second) {
		return 0, fmt.Errorf("revive: timestamp %d outside freshness window (now %d)", ts, now)
	}

	mac := hmac.New(sha256.New, e.key)
	mac.Write(p[0:22])
	expected := mac.Sum(nil)[:14]
	if !hmac.Equal(p[22:36], expected) {
		return 0, errors.New("revive: bad authentication tag")
	}

	e.mu.Lock()
	var digest [16]byte
	copy(digest[:], p[14:30]) // nonce + first 8 bytes of tag
	for _, s := range e.seenRing {
		if s == digest {
			e.mu.Unlock()
			return 0, errors.New("revive: replay detected")
		}
	}
	e.seenRing[e.seenIdx%len(e.seenRing)] = digest
	e.seenIdx++
	e.mu.Unlock()

	if e.onRevive != nil {
		e.onRevive(action, src)
	}
	return action, nil
}

// FormatDNSQuery packages a 36-byte knock into an RFC 1035 DNS A query.
func FormatDNSQuery(knock []byte) []byte {
	token := strings.ToLower(b32Hex.EncodeToString(knock))
	var txID [2]byte
	_, _ = rand.Read(txID[:])

	// Header: 12 bytes
	hdr := []byte{
		txID[0], txID[1],
		0x01, 0x00, // Flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Question: <token>.revive.internal
	var q []byte
	q = append(q, byte(len(token)))
	q = append(q, token...)
	q = append(q, 6)
	q = append(q, "revive"...)
	q = append(q, 8)
	q = append(q, "internal"...)
	q = append(q, 0x00)       // null root
	q = append(q, 0x00, 0x01) // QTYPE: A (1)
	q = append(q, 0x00, 0x01) // QCLASS: IN (1)

	return append(hdr, q...)
}

// ParseDNSQueryKnock attempts to extract a knock payload from a raw DNS query packet.
func ParseDNSQueryKnock(dnsPkt []byte) ([]byte, bool) {
	if len(dnsPkt) < 12 {
		return nil, false
	}
	// Skip header (12 bytes) and read first label
	pos := 12
	if pos >= len(dnsPkt) {
		return nil, false
	}
	labelLen := int(dnsPkt[pos])
	pos++
	if labelLen == 0 || pos+labelLen > len(dnsPkt) {
		return nil, false
	}
	token := string(dnsPkt[pos : pos+labelLen])
	decoded, err := b32Hex.DecodeString(strings.ToUpper(token))
	if err != nil || len(decoded) < 36 {
		return nil, false
	}
	if binary.BigEndian.Uint32(decoded[0:4]) != ReviveMagic {
		return nil, false
	}
	return decoded, true
}
