package wat

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Encrypted Client Hello for the client side (-ech). The ECHConfigList either comes from the user (base64) or is
// fetched from the HTTPS DNS record (type 65) of the SNI name over DNS-over-HTTPS addressed by IP, never through the
// system resolver. The handshake itself is the standard library's (or utls's) ECH.

// dohServers are tried in order, addressed by IP so no DNS lookup is needed to reach them. A variable for tests.
var dohServers = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"}

const (
	dnsTypeHTTPS = 65
	svcParamECH  = 5
	echNegTTL    = 5 * time.Minute
	echPosTTL    = time.Hour
)

type echEntry struct {
	list []byte
	at   time.Time
}

// echState caches the ECHConfigList per name.
type echState struct {
	mode   string // "off", "auto" or "static"
	static []byte

	mu sync.Mutex
	m  map[string]*echEntry
}

// ParseECHFlag validates a -ech value: off, auto or a base64 ECHConfigList.
func ParseECHFlag(s string) (mode string, list []byte, err error) {
	switch s = strings.TrimSpace(s); s {
	case "", "off":
		return "off", nil, nil
	case "auto":
		return "auto", nil, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			if len(b) < 6 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
				return "", nil, errors.New("-ech: not an ECHConfigList (length prefix does not match)")
			}
			return "static", b, nil
		}
	}
	return "", nil, errors.New("-ech must be off, auto or a base64 ECHConfigList")
}

func newECHState(v string) (*echState, error) {
	mode, list, err := ParseECHFlag(v)
	if err != nil {
		return nil, err
	}
	return &echState{mode: mode, static: list, m: map[string]*echEntry{}}, nil
}

// get returns the ECHConfigList to offer for name, or nil to connect without ECH.
func (s *echState) get(ctx context.Context, name string, e *tlsEngine) []byte {
	switch s.mode {
	case "off":
		return nil
	case "static":
		s.mu.Lock()
		defer s.mu.Unlock()
		if en := s.m[""]; en != nil {
			return en.list
		}
		return s.static
	}
	if name == "" {
		e.note("ech-noname", "ech auto: needs a name to look up (set -sni or -host); connecting without ECH")
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock() // held over the fetch: concurrent slots wait for one lookup instead of making eight
	if en := s.m[name]; en != nil {
		ttl := echPosTTL
		if en.list == nil {
			ttl = echNegTTL
		}
		if time.Since(en.at) < ttl {
			return en.list
		}
	}
	fctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	list, err := FetchECHConfigList(fctx, name)
	switch {
	case err != nil:
		e.note("ech-fetch:"+name, "ech auto: no ECH config for %s (%v); connecting without ECH", name, err)
		list = nil
	default:
		e.note("ech-ok:"+name, "ech auto: using the ECH config published for %s (%d bytes)", name, len(list))
	}
	s.m[name] = &echEntry{list: list, at: time.Now()}
	return list
}

// rejected records the server's retry configs after an ECH rejection and says whether to redial. Without retry
// configs the server does not do ECH: with auto we continue without it, with a fixed list it is an error.
func (s *echState) rejected(name string, retry []byte, e *tlsEngine) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(retry) > 0 {
		key := name
		if s.mode == "static" {
			key = ""
		}
		s.m[key] = &echEntry{list: retry, at: time.Now()}
		e.note("ech-retry", "ech: the server rejected our ECH config and sent a new one; retrying with it")
		return true
	}
	if s.mode == "auto" {
		s.m[name] = &echEntry{list: nil, at: time.Now()}
		e.note("ech-none:"+name, "ech auto: %s rejected ECH without new configs; connecting without ECH", name)
		return true
	}
	return false
}

// FetchECHConfigList looks up the ECH SvcParam of name's HTTPS record through the DoH servers.
func FetchECHConfigList(ctx context.Context, name string) ([]byte, error) {
	q, err := buildDNSQuery(name, dnsTypeHTTPS)
	if err != nil {
		return nil, err
	}
	var last error
	for _, srv := range dohServers {
		list, err := dohQuery(ctx, srv, q)
		if err == nil {
			return list, nil
		}
		last = fmt.Errorf("%s: %w", srv, err)
	}
	return nil, last
}

func dohQuery(ctx context.Context, server string, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", server+"?dns="+base64.RawURLEncoding.EncodeToString(q), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("DoH answered " + resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseHTTPSECH(body, q)
}

func buildDNSQuery(name string, qtype uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var id [2]byte
	if _, err := crand.Read(id[:]); err != nil {
		return nil, err
	}
	b := []byte{id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0} // RD, one question
	if name == "" {
		return nil, errors.New("empty name")
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, fmt.Errorf("bad DNS name %q", name)
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b, nil
}

// dnsSkipName returns the offset after the (possibly compressed) name starting at off.
func dnsSkipName(m []byte, off int) (int, error) {
	for hops := 0; off < len(m) && hops < 128; hops++ {
		c := int(m[off])
		switch {
		case c == 0:
			return off + 1, nil
		case c&0xc0 == 0xc0:
			if off+2 > len(m) {
				return 0, errors.New("truncated DNS name")
			}
			return off + 2, nil
		case c&0xc0 != 0:
			return 0, errors.New("bad DNS label")
		}
		off += 1 + c
	}
	return 0, errors.New("truncated DNS name")
}

// parseHTTPSECH extracts the ech SvcParam from the HTTPS answers of a DNS response (q is the query it answers,
// used to check the id; nil skips that).
func parseHTTPSECH(m, q []byte) ([]byte, error) {
	if len(m) < 12 {
		return nil, errors.New("short DNS response")
	}
	if q != nil && (len(q) < 2 || m[0] != q[0] || m[1] != q[1]) {
		return nil, errors.New("DNS response id mismatch")
	}
	if rc := m[3] & 0x0f; rc != 0 {
		return nil, fmt.Errorf("DNS rcode %d", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = dnsSkipName(m, off); err != nil {
			return nil, err
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if off, err = dnsSkipName(m, off); err != nil {
			return nil, err
		}
		if off+10 > len(m) {
			return nil, errors.New("truncated DNS record")
		}
		typ, rdlen := binary.BigEndian.Uint16(m[off:]), int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return nil, errors.New("truncated DNS rdata")
		}
		rd := m[off : off+rdlen]
		off += rdlen
		if typ != dnsTypeHTTPS || len(rd) < 3 {
			continue
		}
		if binary.BigEndian.Uint16(rd) == 0 { // AliasMode: no params here
			continue
		}
		p, err := dnsSkipName(rd, 2) // target name (never compressed in RDATA, skip tolerates it)
		if err != nil {
			continue
		}
		for p+4 <= len(rd) {
			key, l := binary.BigEndian.Uint16(rd[p:]), int(binary.BigEndian.Uint16(rd[p+2:]))
			p += 4
			if p+l > len(rd) {
				break
			}
			if key == svcParamECH && l >= 6 {
				return append([]byte(nil), rd[p:p+l]...), nil
			}
			p += l
		}
	}
	return nil, errors.New("the HTTPS record has no ech parameter")
}
