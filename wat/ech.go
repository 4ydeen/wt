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
	"os"
	"strings"
	"sync"
	"time"
)

// Encrypted Client Hello for the client side (-ech). The ECHConfigList either comes from the user (base64) or is
// fetched from the HTTPS DNS record (type 65) of the SNI name over DNS-over-HTTPS addressed by IP, never through the
// system resolver. The handshake itself is the standard library's (or utls's) ECH.

// dohServers are raced in parallel (first answer wins), addressed by IP so no DNS lookup is needed to reach them.
// Some are blocked on some networks (1.1.1.1 from Iran, say), so none may be relied on. A variable for tests.
var dohServers = []string{"https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"}

const (
	dnsTypeHTTPS = 65
	svcParamECH  = 5
	echNegTTL    = 5 * time.Minute  // the name publishes no ech parameter
	echErrTTL    = 30 * time.Second // the lookup itself failed (DoH blocked): try again soon
	echPosTTL    = time.Hour
	dohTimeout   = 3 * time.Second // per DoH server; they are queried in parallel
)

// errNoECH: DNS answered, but the name has no ech parameter (a definitive answer, unlike a failed lookup).
var errNoECH = errors.New("the HTTPS record has no ech parameter")

type echEntry struct {
	list []byte
	next time.Time // when to look the name up again
}

// echState caches the ECHConfigList per name.
type echState struct {
	mode   string // "off", "auto", "ladder" or "static"
	static []byte

	// ladder (2.9.0): when the direct DoH servers all fail, the query goes through this hook instead
	// (cmd/wattun wires it to the tunnel's built-in DNS relay, server target port 53). nil = behave as auto.
	ladder func(query []byte) ([]byte, error)

	mu       sync.Mutex
	m        map[string]*echEntry
	inflight map[string]bool // background refreshes running

	cachePath   string // -ech-cache file ("" = off)
	cacheLoaded bool
	cacheWarned bool
}

// ParseECHFlag validates a -ech value: off, auto, ladder or a base64 ECHConfigList.
func ParseECHFlag(s string) (mode string, list []byte, err error) {
	switch s = strings.TrimSpace(s); s {
	case "", "off":
		return "off", nil, nil
	case "auto":
		return "auto", nil, nil
	case "ladder":
		return "ladder", nil, nil
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

func newECHState(v, cachePath string) (*echState, error) {
	mode, list, err := ParseECHFlag(v)
	if err != nil {
		return nil, err
	}
	if mode != "auto" {
		cachePath = ""
	}
	return &echState{mode: mode, static: list, m: map[string]*echEntry{}, inflight: map[string]bool{}, cachePath: cachePath}, nil
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
	case "ladder":
		return s.getLadder(ctx, name, e)
	}
	if name == "" {
		e.note("ech-noname", "ech auto: needs a name to look up (set -sni or -host); connecting without ECH")
		return nil
	}
	s.mu.Lock()
	s.loadCacheLocked(e)
	en := s.m[name]
	if en != nil && time.Now().Before(en.next) {
		defer s.mu.Unlock()
		return en.list
	}
	if en != nil && en.list != nil { // known config, due for a refresh: use it now, refresh behind the scenes
		list := en.list
		s.mu.Unlock()
		s.refreshAsync(name, e)
		return list
	}
	// held over the first fetch: concurrent slots wait for one lookup instead of making eight
	defer s.mu.Unlock()
	s.lookupLocked(name, e)
	return s.m[name].list
}

// getLadder is auto plus the second rung: when the direct DoH lookup fails (all servers unreachable), the
// query goes through the tunnel's DNS relay. A name with no ech parameter still ends the ladder (definitive).
func (s *echState) getLadder(ctx context.Context, name string, e *tlsEngine) []byte {
	if name == "" {
		e.note("ech-noname", "ech ladder: needs a name to look up (set -sni or -host); connecting without ECH")
		return nil
	}
	s.mu.Lock()
	s.loadCacheLocked(e)
	en := s.m[name]
	if en != nil && time.Now().Before(en.next) {
		defer s.mu.Unlock()
		return en.list
	}
	if en != nil && en.list != nil {
		list := en.list
		s.mu.Unlock()
		s.refreshAsync(name, e)
		return list
	}
	defer s.mu.Unlock()
	s.lookupLocked(name, e)
	return s.m[name].list
}

// lookupLocked fetches name's config (s.mu held). The lookup does not use the dial's context, so a slow DoH cannot eat
// the dial's budget. A failed lookup never drops a config we already have (stale-while-error).
func (s *echState) lookupLocked(name string, e *tlsEngine) {
	fctx, cancel := context.WithTimeout(context.Background(), dohTimeout+time.Second)
	defer cancel()
	list, err := FetchECHConfigList(fctx, name)
	if err != nil && !errors.Is(err, errNoECH) && s.mode == "ladder" && s.ladder != nil {
		if l2, err2 := s.ladderThrough(name); err2 == nil {
			list, err = l2, nil
			e.note("ech-ladder:"+name, "ech ladder: direct DoH failed (%v); fetched the config through the tunnel relay", err)
		} else {
			e.note("ech-ladder:"+name, "ech ladder: direct DoH failed and the relay could not answer (%v)", err2)
		}
	}
	old := s.m[name]
	switch {
	case err == nil:
		e.note("ech-ok:"+name, "ech auto: using the ECH config published for %s (%d bytes)", name, len(list))
		s.m[name] = &echEntry{list: list, next: time.Now().Add(echPosTTL)}
		s.saveCacheLocked(e)
	case errors.Is(err, errNoECH) && (old == nil || old.list == nil):
		e.note("ech-fetch:"+name, "ech auto: no ECH config for %s (%v); connecting without ECH", name, err)
		s.m[name] = &echEntry{next: time.Now().Add(echNegTTL)}
	default: // lookup failed (or the record vanished): keep what we know, try again soon
		var keep []byte
		if old != nil {
			keep = old.list
		}
		if keep != nil {
			e.note("ech-stale:"+name, "ech auto: could not refresh the ECH config for %s (%v); keeping the old one", name, err)
		} else {
			e.note("ech-fetch:"+name, "ech auto: no ECH config for %s (%v); connecting without ECH", name, err)
		}
		s.m[name] = &echEntry{list: keep, next: time.Now().Add(echErrTTL)}
	}
}

// ladderThrough runs one DoH query through the fallback hook (2.9.0): build the HTTPS-record query, get the
// answer from the hook, parse the ech SvcParam out of it.
func (s *echState) ladderThrough(name string) ([]byte, error) {
	q, err := buildDNSQuery(name, dnsTypeHTTPS)
	if err != nil {
		return nil, err
	}
	ans, err := s.ladder(q)
	if err != nil {
		return nil, err
	}
	return parseHTTPSECH(ans, q)
}

func (s *echState) refreshAsync(name string, e *tlsEngine) {	s.mu.Lock()
	if s.inflight[name] {
		s.mu.Unlock()
		return
	}
	s.inflight[name] = true
	s.mu.Unlock()
	go func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.lookupLocked(name, e)
		delete(s.inflight, name)
	}()
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
		s.m[key] = &echEntry{list: retry, next: time.Now().Add(echPosTTL)}
		s.saveCacheLocked(e)
		e.note("ech-retry", "ech: the server rejected our ECH config and sent a new one; retrying with it")
		if s.mode == "auto" && name != "" { // also re-read DNS in the background (the keys rotated)
			go func() {
				time.Sleep(2 * time.Second) // let the retry connection win first; the refresh must not stall it
				s.mu.Lock()
				defer s.mu.Unlock()
				if s.inflight[name] {
					return
				}
				s.inflight[name] = true
				defer delete(s.inflight, name)
				s.lookupLocked(name, e)
			}()
		}
		return true
	}
	if s.mode == "auto" {
		s.m[name] = &echEntry{next: time.Now().Add(echNegTTL)}
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
	type res struct {
		list []byte
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan res, len(dohServers))
	for _, srv := range dohServers {
		go func() {
			list, err := dohQuery(ctx, srv, q)
			if err != nil && !errors.Is(err, errNoECH) {
				err = fmt.Errorf("%s: %w", srv, err)
			}
			ch <- res{list, err}
		}()
	}
	var last error
	noECH := false
	var grace <-chan time.Time
	for n := 0; n < len(dohServers); n++ {
		select {
		case r := <-ch:
			switch {
			case r.err == nil:
				return r.list, nil
			case errors.Is(r.err, errNoECH):
				if !noECH { // a resolver may lag behind the others: give them a moment to produce a config
					noECH = true
					grace = time.After(400 * time.Millisecond)
				}
			default:
				last = r.err
			}
		case <-grace:
			return nil, errNoECH
		case <-ctx.Done():
			n = len(dohServers)
			if last == nil {
				last = ctx.Err()
			}
		}
	}
	if noECH {
		return nil, errNoECH
	}
	return nil, last
}

func dohQuery(ctx context.Context, server string, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
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
	return nil, errNoECH
}

// ---------------------------------------------------------------- -ech-cache (2.2.3)
// The cache file holds one line per name: "name base64(ECHConfigList)". It lets a restart start with the last good
// config at once (DoH may be blocked or slow) while the normal refresh runs in the background. Errors never stop
// the tunnel: the first one is logged, the rest are silent.

func (s *echState) cacheErr(e *tlsEngine, what string, err error) {
	if s.cacheWarned {
		return
	}
	s.cacheWarned = true
	e.note("ech-cache", "ech-cache %s: %s: %v (continuing without the cache)", what, s.cachePath, err)
}

// loadCacheLocked seeds s.m from the cache file once (s.mu held). Seeded entries are due at once, so the first use
// returns the cached config and refreshes it behind the scenes.
func (s *echState) loadCacheLocked(e *tlsEngine) {
	if s.cachePath == "" || s.cacheLoaded {
		return
	}
	s.cacheLoaded = true
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.cacheErr(e, "read", err)
		}
		return
	}
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 || s.m[f[0]] != nil {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(b) < 6 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
			continue
		}
		s.m[f[0]] = &echEntry{list: b} // next is zero: due for a refresh
	}
}

// saveCacheLocked writes every known config atomically (tmp + rename, 0600) (s.mu held).
func (s *echState) saveCacheLocked(e *tlsEngine) {
	if s.cachePath == "" {
		return
	}
	var sb strings.Builder
	for name, en := range s.m {
		if name != "" && en.list != nil {
			sb.WriteString(name + " " + base64.StdEncoding.EncodeToString(en.list) + "\n")
		}
	}
	tmp := s.cachePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		s.cacheErr(e, "write", err)
		return
	}
	if err := os.Rename(tmp, s.cachePath); err != nil {
		os.Remove(tmp)
		s.cacheErr(e, "write", err)
	}
}
