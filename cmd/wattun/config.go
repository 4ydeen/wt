package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The config file is a tiny YAML subset: `key: value` lines (keys are the flag names), `#` comments, values
// optionally in "double" or 'single' quotes, and one list
//
//	ports:
//	  - 10001
//	  - 10001/udp
//	  - 8443:443       (client listens on 8443, forwards to server port 443; also 5353:53/udp)
//
// A plain N means listen N -> target N. The server's allowlist is the TARGET ports; the client opens the LISTEN ports.
//
// A second list `limits:` holds `- PORT rate=5MB quota=100GB` items (see ports.go). The lists are hot-reloaded (see cfgWatcher); every other key needs a restart.

type portSpec struct {
	Port   int // public (client listen) port
	Target int // server port it forwards to (== Port for a plain `N` item)
	UDP    bool
}

// portMap is one client listener: public port Listen forwards to server port Target.
type portMap struct{ Listen, Target int }

type kv struct{ Key, Val string }

type fileConfig struct {
	KVs      []kv // in file order; repeated keys are kept (only "header" may repeat)
	Ports    []portSpec
	PortsSet bool        // a `ports:` key was present (an empty list then means "no ports")
	Limits   []limitSpec // `limits:` list: per-port rate / quota (hot-reloaded)
}

// tcpPorts / udpPorts are the server-side (target) ports, i.e. the allowlist.
func (c *fileConfig) tcpPorts() []int { return c.targets(false) }
func (c *fileConfig) udpPorts() []int { return c.targets(true) }

func (c *fileConfig) targets(udp bool) []int {
	var out []int
	for _, p := range c.Ports {
		if p.UDP == udp {
			out = append(out, p.Target)
		}
	}
	return out
}

// tcpMaps / udpMaps are the client-side listen->target mappings.
func (c *fileConfig) tcpMaps() []portMap { return c.maps(false) }
func (c *fileConfig) udpMaps() []portMap { return c.maps(true) }

func (c *fileConfig) maps(udp bool) []portMap {
	var out []portMap
	for _, p := range c.Ports {
		if p.UDP == udp {
			out = append(out, portMap{p.Port, p.Target})
		}
	}
	return out
}

// plainMaps maps each port to itself.
func plainMaps(ports []int) []portMap {
	out := make([]portMap, len(ports))
	for i, p := range ports {
		out[i] = portMap{p, p}
	}
	return out
}

func (c *fileConfig) get(key string) (string, bool) {
	for i := len(c.KVs) - 1; i >= 0; i-- {
		if c.KVs[i].Key == key {
			return c.KVs[i].Val, true
		}
	}
	return "", false
}

// parseConfig parses txt; known (if non-nil) says which keys exist - anything else is an error.
func parseConfig(txt string, known func(string) bool) (*fileConfig, error) {
	cfg := &fileConfig{}
	seen := map[string]bool{}
	limitsSeen := false
	list := "" // which list the indented "- item" lines belong to: "ports", "limits" or ""
	for n, line := range strings.Split(txt, "\n") {
		ln := n + 1
		raw := strings.TrimRight(line, "\r")
		t := strings.TrimSpace(stripComment(raw))
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "- ") || t == "-" {
			item := unquote(strings.TrimSpace(t[1:]))
			switch list {
			case "ports":
				ps, err := parsePortItem(item)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", ln, err)
				}
				for _, o := range cfg.Ports {
					if o.Port == ps.Port && o.UDP == ps.UDP {
						proto := "tcp"
						if ps.UDP {
							proto = "udp"
						}
						return nil, fmt.Errorf("line %d: duplicate listen port %d/%s", ln, ps.Port, proto)
					}
				}
				cfg.Ports = append(cfg.Ports, ps)
			case "limits":
				ls, err := parseLimitItem(item)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", ln, err)
				}
				cfg.Limits = append(cfg.Limits, ls)
			default:
				return nil, fmt.Errorf("line %d: list item outside of ports: / limits:", ln)
			}
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if list == "" {
				return nil, fmt.Errorf("line %d: unexpected indentation", ln)
			}
		}
		list = ""
		k, v, ok := strings.Cut(t, ":")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("line %d: want 'key: value'", ln)
		}
		v = unquote(strings.TrimSpace(v))
		if k == "ports" {
			if v != "" {
				return nil, fmt.Errorf("line %d: ports: takes a list of '- PORT' lines", ln)
			}
			if cfg.PortsSet {
				return nil, fmt.Errorf("line %d: duplicate key ports", ln)
			}
			cfg.PortsSet, list = true, "ports"
			continue
		}
		if k == "limits" {
			if v != "" {
				return nil, fmt.Errorf("line %d: limits: takes a list of '- PORT rate=... quota=...' lines", ln)
			}
			if limitsSeen {
				return nil, fmt.Errorf("line %d: duplicate key limits", ln)
			}
			limitsSeen, list = true, "limits"
			continue
		}
		if known != nil && !known(k) {
			return nil, fmt.Errorf("line %d: unknown key %q", ln, k)
		}
		if seen[k] && k != "header" {
			return nil, fmt.Errorf("line %d: duplicate key %q", ln, k)
		}
		seen[k] = true
		cfg.KVs = append(cfg.KVs, kv{k, v})
	}
	return cfg, nil
}

// stripComment removes a trailing `# ...` that is outside quotes and starts a line or follows whitespace.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func parsePortItem(s string) (portSpec, error) {
	var ps portSpec
	if p, ok := strings.CutSuffix(s, "/udp"); ok {
		s, ps.UDP = p, true
	} else if p, ok := strings.CutSuffix(s, "/tcp"); ok {
		s = p
	}
	l, t, mapped := strings.Cut(s, ":")
	port := func(x string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("bad port %q", x)
		}
		return n, nil
	}
	var err error
	if ps.Port, err = port(l); err != nil {
		return ps, err
	}
	ps.Target = ps.Port
	if mapped {
		if ps.Target, err = port(t); err != nil {
			return ps, err
		}
	}
	return ps, nil
}

// cfgWatcher polls the config file like -allow-file: a changed ports list is handed to onPorts, any other changed
// key is reported as "restart needed". A file that fails to parse keeps the previous state.
type cfgWatcher struct {
	path     string
	known    func(string) bool
	skip     func(key string) bool // keys overridden on the command line: the file value is not in effect
	onPorts  func(*fileConfig)
	onLimits func(*fileConfig) // optional
	interval time.Duration

	mu     sync.Mutex
	mtime  time.Time
	size   int64
	base   map[string]string // effective non-port values (key -> joined values) at startup
	ports  string
	limits string
}

func flatten(c *fileConfig) map[string]string {
	m := map[string]string{}
	for _, e := range c.KVs {
		if old, ok := m[e.Key]; ok {
			m[e.Key] = old + "\x00" + e.Val
		} else {
			m[e.Key] = e.Val
		}
	}
	return m
}

func portsKey(c *fileConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%v", c.PortsSet)
	for _, p := range c.Ports {
		fmt.Fprintf(&b, ",%d:%d/%v", p.Port, p.Target, p.UDP)
	}
	return b.String()
}

// start records the startup config as the baseline (the file was already parsed and applied by the caller).
func (w *cfgWatcher) start(initial *fileConfig) {
	w.base, w.ports, w.limits = flatten(initial), portsKey(initial), limitsKey(initial)
	if st, err := os.Stat(w.path); err == nil {
		w.mtime, w.size = st.ModTime(), st.Size()
	}
}

func (w *cfgWatcher) run() {
	for range time.Tick(w.interval) {
		w.check()
	}
}

// check performs one poll.
func (w *cfgWatcher) check() {
	w.mu.Lock()
	defer w.mu.Unlock()
	st, err := os.Stat(w.path)
	if err != nil || (st.ModTime().Equal(w.mtime) && st.Size() == w.size) {
		return
	}
	b, err := os.ReadFile(w.path)
	if err != nil {
		return
	}
	cfg, err := parseConfig(string(b), w.known)
	w.mtime, w.size = st.ModTime(), st.Size() // a broken file is not re-parsed (and re-logged) until it changes again
	if err != nil {
		log.Printf("config %s: %v (keeping the previous config)", w.path, err)
		return
	}
	now := flatten(cfg)
	for k, v := range now {
		if old, ok := w.base[k]; (!ok || old != v) && (w.skip == nil || !w.skip(k)) {
			log.Printf("config: restart needed for %s", k)
			w.base[k] = v
		}
	}
	for k := range w.base {
		if _, ok := now[k]; !ok && (w.skip == nil || !w.skip(k)) {
			log.Printf("config: restart needed for %s (removed)", k)
			delete(w.base, k)
		}
	}
	if pk := portsKey(cfg); pk != w.ports {
		w.ports = pk
		w.onPorts(cfg)
	}
	if lk := limitsKey(cfg); lk != w.limits {
		w.limits = lk
		if w.onLimits != nil {
			w.onLimits(cfg)
		}
	}
}
