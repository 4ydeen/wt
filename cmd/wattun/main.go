// wattun: TCP port forwarding over ICMP echo with its own transport (see ../../README.md).
//
//	server:  wattun -mode server -key SECRET
//	client:    wattun -mode client -key SECRET -peer 203.0.113.10 -map 20030:20030
//
// -map is listenPort:serverPort[,...]; the server connects each stream to 127.0.0.1:serverPort.
// -config FILE.yml supplies flags (command-line flags win) and a hot-reloaded `ports:` list; -reverse swaps which
// side dials the pool carriers (see config.go and wat/carrier_reverse.go) and which side sends the ICMP requests.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"sync"
	"syscall"
	"time"

	"github.com/JohnWatsoon/WatTunnel/wat"
)

var carrierNames = []string{"icmp", "udp", "tcp", "tls", "ws", "wss", "h2", "h2c", "grpc"}

var validCarrier = map[string]bool{"icmp": true, "udp": true, "tcp": true, "tls": true, "ws": true, "wss": true, "h2": true, "h2c": true, "grpc": true}

var poolCarriers = map[string]bool{"tcp": true, "tls": true, "ws": true, "wss": true, "h2": true, "h2c": true, "grpc": true}

func main() {
	mode := flag.String("mode", "", "client|server")
	key := flag.String("key", "", "pre-shared key")
	keyFile := flag.String("key-file", "", "read the key from a file")
	peer := flag.String("peer", "", "client: server IP")
	maps := flag.String("map", "", "client: listenPort:serverPort[,...]")
	udpMaps := flag.String("udp", "", "client: UDP forwarding, PORT or listenPort:serverPort[@bind][,...] (both ends need wattun >= 1.2.0)")
	udpIdle := flag.Duration("udp-idle", 60*time.Second, "UDP flows with no traffic for this long are closed")
	bind := flag.String("bind", "0.0.0.0", "client: listen address")
	offset := flag.Int("port-offset", 0, "client: add this to every listen port (second slot)")
	lanes := flag.Int("lanes", 4, "client: ICMP identifiers to stripe over")
	maxMB := flag.Float64("max-mbps", 16, "pace ceiling, MB/s per direction")
	slackMs := flag.Int("slack-ms", 8, "tolerated RTT growth before slowing down, ms")
	metrics := flag.String("metrics", "", "serve JSON stats on this address (e.g. 127.0.0.1:19700)")
	allowLo := flag.Int("allow-min", 1, "server: lowest target port a client may ask for")
	allowHi := flag.Int("allow-max", 65535, "server: highest target port")
	allowList := flag.String("allow-ports", "", "server: comma list of target ports clients may reach (overrides allow-min/max)")
	allowFile := flag.String("allow-file", "", "server: file with the allowed target ports (comma/space/newline separated), re-read when it changes; overrides -allow-ports")
	debug := flag.Bool("debug", false, "log every stream open/close")
	version := flag.Bool("version", false, "print the version and exit")
	fecMode := flag.String("fec", "off", "off|auto: adaptive XOR parity after bursts of small packets (cuts tail latency on lossy links; both ends need 1.7.0 and -fec auto)")
	hedge := flag.Bool("hedge", false, "send small young packets twice (extra packets, helps lossy tails)")
	lossCeil := flag.Bool("loss-ceiling", false, "pacer: also cut the rate when loss jumps far above its learned baseline (opt-in; default: delay only)")
	icmpType := flag.String("icmp-type", "echo", "icmp carrier: echo|timestamp|info|mask - the ICMP request type the client sends (the server answers with the matching reply: 8/0, 13/14, 15/16, 17/18); both ends must use the same")
	carrier := flag.String("carrier", "icmp", "icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc (all but icmp: client dials -peer host:port, server listens on -listen); join several with '+' (icmp+udp+tcp) to bond them into ONE session that survives any one being blocked; then -peer / -listen are the defaults and -peer-NAME / -listen-NAME (e.g. -peer-udp, -listen-tcp, also keys in the config file) override them per carrier")
	udpListen := flag.String("listen", ":4443", "server, udp carrier: address to listen on")
	conns := flag.Int("conns", wat.DefaultPoolConns, "client, tcp/tls carrier: connections in the pool")
	tlsCert := flag.String("tls-cert", "", "server, tls carrier: certificate file (empty = self-signed in memory)")
	tlsKey := flag.String("tls-key", "", "server, tls carrier: private key file")
	sni := flag.String("sni", "", "client, tls carrier: server name sent in the ClientHello")
	tlsPin := flag.String("tls-pin", "", "client, tls carrier: hex sha256 of the server certificate to require")
	mtu := flag.Int("mtu", 0, "datagram size cap incl. header/tag, 256-1400 (tcp|tls|ws|wss|h2|h2c|grpc: up to 16384) (0 = the carrier default: 640 icmp, 1400 udp, 4096 tcp-based)")
	path := flag.String("path", "/wat", "client/server, ws|wss|h2|h2c|grpc carrier: URL path (grpc: service name, requests go to <path>/Tun)")
	host := flag.String("host", "", "client, ws|wss|h2|h2c|grpc carrier: Host header / authority (default: -peer)")
	plain := flag.Bool("plain", false, "grpc carrier: cleartext h2c instead of TLS (behind a proxy that terminates TLS)")
	reverse := flag.Bool("reverse", false, "tcp|tls|ws|wss|h2|h2c|grpc carriers: the client listens on -listen and the server dials -peer; icmp carrier: the server sends the requests to -peer (the client's IP) and the client answers with replies (both ends need wattun >= 2.0.0 and -reverse)")
	peerBy, listenBy := map[string]*string{}, map[string]*string{}
	for _, c := range carrierNames {
		peerBy[c] = flag.String("peer-"+c, "", "client, bonded carriers: server address of the "+c+" carrier (default: -peer)")
		if c != "icmp" {
			listenBy[c] = flag.String("listen-"+c, "", "server (or -reverse client), bonded carriers: listen address of the "+c+" carrier (default: -listen)")
		}
	}
	cfgPath := flag.String("config", "", "YAML-subset config file: keys are flag names, plus a ports: list (hot-reloaded); command-line flags win")
	var hdrs []string
	flag.Func("header", "client, ws|wss|h2|h2c|grpc carrier: extra request header 'Name: value' (repeatable)", func(v string) error {
		if !strings.Contains(v, ":") {
			return fmt.Errorf("want 'Name: value'")
		}
		hdrs = append(hdrs, v)
		return nil
	})
	flag.Parse()
	if *version {
		fmt.Println("wattun " + wat.Version)
		return
	}
	var fileCfg *fileConfig
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	known := func(k string) bool { return k != "config" && k != "version" && flag.Lookup(k) != nil }
	if *cfgPath != "" {
		b, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		if fileCfg, err = parseConfig(string(b), known); err != nil {
			log.Fatalf("config %s: %v", *cfgPath, err)
		}
		for _, e := range fileCfg.KVs {
			if explicit[e.Key] {
				continue
			}
			if err := flag.Set(e.Key, e.Val); err != nil {
				log.Fatalf("config %s: %s: %v", *cfgPath, e.Key, err)
			}
		}
	}
	debugOn = *debug
	wat.SetLossCeiling(*lossCeil)
	if _, _, ok := wat.ICMPTypes(*icmpType); !ok {
		log.Fatalf("-icmp-type must be echo, timestamp, info or mask, got %q", *icmpType)
	}
	if *fecMode != "off" && *fecMode != "auto" {
		log.Fatalf("-fec must be off or auto, got %q", *fecMode)
	}

	k := []byte(*key)
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		k = []byte(strings.TrimSpace(string(b)))
	}
	if len(k) == 0 || (*mode != "client" && *mode != "server") {
		fmt.Fprintln(os.Stderr, "usage: wattun -mode client|server -key SECRET [-peer IP -map l:s,...]")
		os.Exit(2)
	}
	server := *mode == "server"
	names := strings.Split(*carrier, "+")
	seen := map[string]bool{}
	anyPool := false
	for _, n := range names {
		if !validCarrier[n] || seen[n] {
			fmt.Fprintln(os.Stderr, "unknown -carrier (icmp|udp|tcp|tls|ws|wss|h2|h2c|grpc, joined with + to bond; each at most once)")
			os.Exit(2)
		}
		seen[n] = true
		anyPool = anyPool || poolCarriers[n]
	}
	if *reverse && !anyPool && !seen["icmp"] {
		fmt.Fprintf(os.Stderr, "-reverse needs icmp or a connection-pool carrier (tcp|tls|ws|wss|h2|h2c|grpc), not %q\n", *carrier)
		os.Exit(2)
	}
	pick := func(by map[string]*string, def, c string) string {
		if v := by[c]; v != nil && *v != "" {
			return *v
		}
		return def
	}
	// build opens one carrier; the single-carrier case is exactly the old code path.
	build := func(carrier string) (pio wat.PacketIO, raw wat.RawIO) {
		peer, listen := pick(peerBy, *peer, carrier), pick(listenBy, *udpListen, carrier)
		lis := server != (*reverse && poolCarriers[carrier]) // which side listens: the server, or the client when -reverse
		var ps *wat.TCPPoolServer
		var pc *wat.TCPPoolClient
		var err error
		switch carrier {
		case "icmp":
			var ic *wat.ICMPIO
			if !*reverse {
				ic, err = wat.NewICMPIOType(server, peer, k, *icmpType)
			} else if ic, err = wat.NewICMPIOReverse(server, true, peer, k, *icmpType); err == nil && server {
				if peer == "" {
					log.Printf("reverse icmp: no -peer (the client's IP) set, so this server only answers; set it so the client's replies are always solicited")
				}
				ic.Knock(*lanes, 5*time.Second)
			}
			if err != nil {
				log.Fatalf("icmp socket: %v", err)
			}
			pio, raw = ic, ic
		case "udp":
			if server {
				raw, err = wat.NewUDPServer(listen)
			} else {
				pio, err = wat.NewUDPClient(peer)
			}
			if err != nil {
				log.Fatalf("udp socket: %v", err)
			}
		case "tcp":
			if lis {
				ps, err = wat.NewTCPPoolServer(listen)
			} else {
				pc, err = wat.NewTCPPoolClient(peer, *conns)
			}
			if err != nil {
				log.Fatalf("tcp carrier: %v", err)
			}
		case "tls":
			if lis {
				ps, err = wat.NewTLSPoolServer(listen, *tlsCert, *tlsKey)
			} else {
				var pin []byte
				if *tlsPin != "" {
					if pin, err = hex.DecodeString(strings.ReplaceAll(*tlsPin, ":", "")); err != nil || len(pin) != 32 {
						log.Fatalf("-tls-pin must be 64 hex chars (sha256)")
					}
				}
				pc, err = wat.NewTLSPoolClient(peer, *conns, wat.TLSClientOptions{ServerName: *sni, PinSHA256: pin})
			}
			if err != nil {
				log.Fatalf("tls carrier: %v", err)
			}
		case "ws", "wss", "h2", "h2c", "grpc":
			secure := carrier == "wss" || carrier == "h2" || carrier == "grpc" && !*plain
			if lis {
				so := wat.HTTPServerOptions{Path: *path, Secure: secure, CertFile: *tlsCert, KeyFile: *tlsKey}
				switch carrier {
				case "ws", "wss":
					ps, err = wat.NewWSPoolServer(listen, so)
				case "grpc":
					ps, err = wat.NewGRPCPoolServer(listen, so)
				default:
					ps, err = wat.NewH2PoolServer(listen, so)
				}
			} else {
				co := wat.HTTPClientOptions{Path: *path, Host: *host, Secure: secure, Headers: map[string]string{}}
				co.TLS.ServerName = *sni
				if *tlsPin != "" {
					if co.TLS.PinSHA256, err = hex.DecodeString(strings.ReplaceAll(*tlsPin, ":", "")); err != nil || len(co.TLS.PinSHA256) != 32 {
						log.Fatalf("-tls-pin must be 64 hex chars (sha256)")
					}
				}
				for _, h := range hdrs {
					k, v, _ := strings.Cut(h, ":")
					co.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
				switch carrier {
				case "ws", "wss":
					pc, err = wat.NewWSPoolClient(peer, *conns, co)
				case "grpc":
					pc, err = wat.NewGRPCPoolClient(peer, *conns, co)
				default:
					pc, err = wat.NewH2PoolClient(peer, *conns, co)
				}
			}
			if err != nil {
				log.Fatalf("%s carrier: %v", carrier, err)
			}
		}
		switch { // pool carriers: who listens and who dials is independent of the session role
		case ps != nil && server:
			raw = ps
		case ps != nil:
			pio = wat.NewReverseListenIO(ps)
		case pc != nil && !server:
			pio = pc
		case pc != nil:
			pc.SetMaxBackoff(30 * time.Second) // the client may be listening on another carrier only
			pc.SetDialLog(carrier+" reverse dial", log.Printf)
			raw = wat.NewReverseDialRaw(pc)
		}
		return
	}
	var pio wat.PacketIO
	var raw wat.RawIO
	if len(names) == 1 {
		pio, raw = build(names[0])
	} else { // bonded: one session over all of them
		var kids []wat.PacketIO
		var raws []wat.RawIO
		var lanesPer []int
		for _, n := range names {
			p, r := build(n)
			kids, raws = append(kids, p), append(raws, r)
			lanesPer = append(lanesPer, 1)
			if n == "icmp" {
				lanesPer[len(lanesPer)-1] = *lanes
			}
		}
		var err error
		if server {
			raw = wat.NewMultiRaw(names, raws)
		} else if pio, err = wat.NewBondIO(kids, wat.BondOptions{Names: names, Lanes: lanesPer}); err != nil {
			log.Fatal(err)
		}
	}
	cfg := wat.Config{
		Server: server, Key: k, Paths: *lanes, MaxBps: *maxMB * 1e6, Slack: time.Duration(*slackMs) * time.Millisecond,
		Logf: log.Printf, Hedge: *hedge, FEC: *fecMode == "auto", MaxPayload: *mtu,
	}
	var sess *wat.Session
	var srv *wat.Server
	var err error
	if server {
		srv = wat.NewServer(cfg, raw)
	} else if sess, err = wat.NewSession(cfg, pio); err != nil {
		log.Fatal(err)
	}
	stats := func() wat.Stats {
		if srv != nil {
			return srv.Stats()
		}
		return sess.Stats()
	}
	alive := func() bool { return srv != nil && srv.Sessions() > 0 || sess != nil && sess.Alive() }
	// rxAge: ms since the last authenticated packet from the peer (server: from any client), -1 if none yet.
	rxAge := func() int64 {
		var t time.Time
		if srv != nil {
			t = srv.LastRecv()
		} else {
			t = sess.LastRecv()
		}
		if t.IsZero() {
			return -1
		}
		return time.Since(t).Milliseconds()
	}
	carrierStats := func() []wat.CarrierStat {
		if srv != nil {
			return srv.CarrierStats()
		}
		return sess.CarrierStats()
	}
	side = "c"
	if server {
		side = "s"
	}
	if *cfgPath != "" {
		portReg.loadQuota(*cfgPath + ".quota.json")
	}
	if fileCfg != nil {
		portReg.applyLimits(fileCfg.Limits)
	}
	go portReg.run()
	log.Printf("wattun %s up (ident base %d, lanes %d, max %.0f MB/s)", *mode, wat.IdentBase(k), *lanes, *maxMB)
	if len(names) > 1 {
		log.Printf("bonded carriers: %s", strings.Join(names, " + "))
	}

	if *metrics != "" {
		fixed, changed := loopbackMetricsAddr(*metrics)
		if changed {
			log.Printf("metrics: %s is not a loopback address; serving on %s instead (it exposes stats, pprof and /speedtest)", *metrics, fixed)
		}
		*metrics = fixed
		if _, p, err := net.SplitHostPort(fixed); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				metricsPort.Store(int32(n))
			}
		}
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(portReg.snapshot(side))
			})
			mux.HandleFunc("/quota/reset", quotaResetHandler)
			if sess != nil {
				mux.HandleFunc("/speedtest", speedTestHandler(sess))
			}
			mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
				st := stats()
				out := map[string]any{
					"pkts_out": st.PktsOut, "pkts_in": st.PktsIn, "bytes_out": st.BytesOut, "bytes_in": st.BytesIn,
					"fec_sent": st.FecSent, "fec_recovered": st.FecRecovered, "retrans": st.Retrans, "send_errors": st.Dropped, "rate_bps": st.RateBps,
						"ceiling_bps": st.CeilingBps, "loss_pct": st.LossPct,
					"srtt_ms": float64(st.SRTT) / 1e6, "min_rtt_ms": float64(st.MinRTT) / 1e6,
					"streams": st.Streams, "inflight": st.Inflight, "alive": alive(), "last_rx_age_ms": rxAge(), "version": wat.Version, "draining": srv != nil && srv.Draining(),
					"sessions": func() int {
						if srv != nil {
							return srv.Sessions()
						}
						return 1
					}(),
					"dgram_sent": st.DgramSent, "dgram_recv": st.DgramRecv, "dgram_dropped_queue": st.DgramDropQueue,
					"dgram_dropped_size": st.DgramDropSize, "dgram_dropped_rx": st.DgramDropRx, "dgram_flows": udpFlowsActive.Load(),
					"dgram_rejected": udpRejected.Load(), "dgram_flow_cap_drops": udpFlowCapDrop.Load(),
				}
				out["ports"] = portReg.snapshot(side)
				if len(names) > 1 {
					out["carriers"] = carrierStats()
				}
				if srv != nil {
					out["clients"] = clientsJSON(srv.Clients())
				}
				json.NewEncoder(w).Encode(out)
			})
			log.Println(http.ListenAndServe(*metrics, mux))
		}()
	}
	go func() {
		var last wat.Stats
		var lw linkWatch
		for range time.Tick(10 * time.Second) {
			st := stats()
			if !server {
				if note := lw.tick(10*time.Second, st.PktsIn, st.PktsOut-last.PktsOut, alive()); note != "" {
					log.Print(note)
				}
			}
			if st.PktsIn == last.PktsIn && st.PktsOut == last.PktsOut && st.Streams == 0 {
				continue
			}
			log.Printf("stats: streams=%d rate=%.1fMB/s srtt=%v min=%v out=%d in=%d retrans=%d errs=%d ceiling=%.1fMB/s loss=%.1f%%", st.Streams, st.RateBps/1e6,
				st.SRTT.Round(time.Millisecond), st.MinRTT.Round(time.Millisecond), st.PktsOut-last.PktsOut, st.PktsIn-last.PktsIn, st.Retrans-last.Retrans, st.Dropped-last.Dropped, st.CeilingBps/1e6, st.LossPct)
			last = st
		}
	}()

	if server {
		var al *allow
		if fileCfg != nil && fileCfg.PortsSet { // the config's ports replace -allow-file / -allow-ports
			al = newAllow("", "")
			al.setPorts(fileCfg.tcpPorts())
			al.setUDPPorts(fileCfg.udpPorts())
		} else {
			al = newAllow(*allowList, *allowFile)
		}
		if *cfgPath != "" {
			w := &cfgWatcher{path: *cfgPath, known: known, skip: func(k string) bool { return explicit[k] }, interval: 3 * time.Second,
				onPorts:  func(c *fileConfig) { al.setPorts(c.tcpPorts()); al.setUDPPorts(c.udpPorts()) },
				onLimits: func(c *fileConfig) { portReg.applyLimits(c.Limits) }}
			w.start(fileCfg)
			go w.run()
		}
		go func() {
			for s := range srv.New {
				go serve(s, *allowLo, *allowHi, al)
				go serveDgrams(s, *allowLo, *allowHi, al, *udpIdle)
			}
		}()
		usr := make(chan os.Signal, 1)
		signal.Notify(usr, drainSignal)
		go func() { // SIGUSR1: stop taking new client sessions, exit once the current ones are gone (handover)
			<-usr
			srv.Drain()
			log.Printf("draining: no new sessions; %d active", srv.Sessions())
			for range time.Tick(2 * time.Second) {
				if srv.Sessions() == 0 {
					log.Printf("drained, exiting")
					os.Exit(0)
				}
			}
		}()
	} else {
		cfgPorts := fileCfg != nil && fileCfg.PortsSet
		if *maps != "" || !cfgPorts && *udpMaps == "" { // without -map and without ports: keep the old "bad -map entry" failure
			for _, m := range strings.Split(*maps, ",") {
				bindAddr := *bind
				if at := strings.Index(m, "@"); at >= 0 { // 18999:18999@127.0.0.1 keeps a port private
					bindAddr = strings.TrimSpace(m[at+1:])
					m = m[:at]
				}
				f := strings.Split(strings.TrimSpace(m), ":")
				if len(f) != 2 {
					log.Fatalf("bad -map entry %q", m)
				}
				lp, e1 := strconv.Atoi(f[0])
				sp, e2 := strconv.Atoi(f[1])
				if e1 != nil || e2 != nil {
					log.Fatalf("bad -map entry %q", m)
				}
				addr := net.JoinHostPort(bindAddr, strconv.Itoa(lp+*offset))
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					log.Fatalf("listen %s: %v", addr, err)
				}
				log.Printf("forwarding %s -> server :%d", addr, sp)
				ps := portReg.get("c", lp+*offset)
				go acceptLoop(ln, func(c net.Conn) { forward(sess, c, sp, ps) })
			}
		}
		dc := newDgramClient(sess, *udpIdle)
		for _, m := range strings.Split(*udpMaps, ",") {
			if strings.TrimSpace(m) == "" {
				continue
			}
			addr, target, err := parseUDPMap(strings.TrimSpace(m), *bind, *offset)
			if err != nil {
				log.Fatal(err)
			}
			if _, err := dc.listen(addr, target); err != nil {
				log.Fatalf("listen udp %s: %v", addr, err)
			}
			log.Printf("forwarding udp %s -> server :%d", addr, target)
		}
		if *cfgPath != "" { // config ports: public port N -> server port N, added and removed live
			uls := newUDPListeners(func(p, t int) (*udpListener, error) {
				addr := net.JoinHostPort(*bind, strconv.Itoa(p+*offset))
				l, err := dc.listen(addr, t)
				if err == nil {
					log.Printf("forwarding udp %s -> server :%d", addr, t)
				}
				return l, err
			})
			ls := newListeners(func(p, t int) (net.Listener, error) {
				addr := net.JoinHostPort(*bind, strconv.Itoa(p+*offset))
				ln, err := net.Listen("tcp", addr)
				if err == nil {
					log.Printf("forwarding %s -> server :%d", addr, t)
					ps := portReg.get("c", p+*offset)
					go acceptLoop(ln, func(c net.Conn) { forward(sess, c, t, ps) })
				}
				return ln, err
			})
			if cfgPorts {
				if errs := ls.apply(fileCfg.tcpMaps()); len(errs) > 0 {
					log.Fatal(errs[0])
				}
				if errs := uls.apply(fileCfg.udpMaps()); len(errs) > 0 {
					log.Fatal(errs[0])
				}
			}
			w := &cfgWatcher{path: *cfgPath, known: known, skip: func(k string) bool { return explicit[k] }, interval: 3 * time.Second,
				onLimits: func(c *fileConfig) { portReg.applyLimits(c.Limits) },
				onPorts: func(c *fileConfig) {
					for _, e := range ls.apply(c.tcpMaps()) {
						log.Print(e)
					}
					for _, e := range uls.apply(c.udpMaps()) {
						log.Print(e)
					}
				}}
			w.start(fileCfg)
			go w.run()
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	portReg.save()
	if srv != nil {
		srv.Close()
	} else {
		sess.Close()
	}
}

// acceptLoop runs handle for every connection until the listener is closed.
func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handle(c)
	}
}

// forward opens a stream to server port target and bridges c to it.
func forward(sess *wat.Session, c net.Conn, target int, ps *portStat) {
	if !ps.track(c) { // quota used up
		c.Close()
		return
	}
	defer ps.untrack(c)
	if !sess.Alive() { // tunnel is down: fail fast so the client retries elsewhere
		ps.errs.Add(1)
		c.Close()
		return
	}
	st, err := sess.OpenStream()
	if err != nil {
		ps.errs.Add(1)
		c.Close()
		return
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(target))
	st.SetGroup(uint32(target)) // fair queuing: one port's heavy streams share the link with the others
	if _, err := st.Write(hdr[:]); err != nil {
		ps.errs.Add(1)
		c.Close()
		return
	}
	dbg("client conn %s -> stream opened", c.RemoteAddr())
	bridge(c, st, fmt.Sprintf("client %s", c.RemoteAddr()), ps, false)
}

// listeners is the live set of public client ports opened from the config's ports list. Closing a listener stops
// new connections only; connections already bridged keep running.
type listeners struct {
	mu     sync.Mutex
	active map[portMap]net.Listener
	open   func(listen, target int) (net.Listener, error)
}

func newListeners(open func(listen, target int) (net.Listener, error)) *listeners {
	return &listeners{active: map[portMap]net.Listener{}, open: open}
}

// apply makes the open listeners equal to want; a changed target for the same listen port is a close + reopen.
// Failures are returned and retried by the next apply.
func (l *listeners) apply(want []portMap) []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	set := map[portMap]bool{}
	for _, m := range want {
		set[m] = true
	}
	for m, ln := range l.active { // close first so a re-targeted listen port can be rebound
		if !set[m] {
			ln.Close()
			delete(l.active, m)
			log.Printf("stopped listening on port %d (-> %d)", m.Listen, m.Target)
		}
	}
	var errs []error
	for _, m := range want {
		if l.active[m] == nil {
			ln, err := l.open(m.Listen, m.Target)
			if err != nil {
				errs = append(errs, fmt.Errorf("listen port %d: %v", m.Listen, err))
				continue
			}
			l.active[m] = ln
		}
	}
	return errs
}

// has reports whether listen port p is open.
func (l *listeners) has(p int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for m := range l.active {
		if m.Listen == p {
			return true
		}
	}
	return false
}

// target returns the target of the open listener on listen port p (0 if none).
func (l *listeners) target(p int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for m := range l.active {
		if m.Listen == p {
			return m.Target
		}
	}
	return 0
}

// metricsPort is the port of the local metrics server (0 when off). The server never forwards a stream to it,
// whatever the allowlist says: it exposes stats, pprof and /speedtest.
var metricsPort atomic.Int32

func isMetricsPort(port int) bool {
	m := int(metricsPort.Load())
	return m != 0 && port == m
}

// loopbackMetricsAddr returns addr unchanged when its host is a loopback IP or "localhost"; otherwise (empty,
// 0.0.0.0, ::, a LAN address, a name) it returns 127.0.0.1:<port> and changed=true.
func loopbackMetricsAddr(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if p := strings.TrimPrefix(addr, ":"); p != "" && !strings.Contains(p, ":") {
			return "127.0.0.1:" + p, true
		}
		return addr, false // unparseable: let ListenAndServe report it
	}
	if strings.EqualFold(host, "localhost") {
		return addr, false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return addr, false
	}
	return net.JoinHostPort("127.0.0.1", port), true
}

func serve(sess *wat.Session, lo, hi int, al *allow) {
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		go func() {
			var hdr [2]byte
			if _, err := io.ReadFull(st, hdr[:]); err != nil {
				st.Reset()
				return
			}
			port := int(binary.BigEndian.Uint16(hdr[:]))
			if port == speedTestPort { // built-in speed test, never a local service
				serveSpeedTest(st)
				return
			}
			if !al.ok(port, lo, hi) {
				st.Reset()
				return
			}
			st.SetGroup(uint32(port))
			ps := portReg.get("s", port)
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
			if err != nil {
				ps.errs.Add(1)
				st.Reset()
				return
			}
			if !ps.track(c) {
				c.Close()
				st.Reset()
				return
			}
			defer ps.untrack(c)
			dbg("server stream -> %d dialed", port)
			bridge(c, st, fmt.Sprintf("server :%d", port), ps, true)
		}()
	}
}

// allow is the set of target ports a client may reach. With a file it is re-read whenever the file changes, so
// adding or removing a port never restarts the server (a restart would cut every client session).
type allow struct {
	mu    sync.RWMutex
	ports map[int]bool
	udp   map[int]bool // udp target ports: `N/udp` entries in the config ports list, -allow-ports or -allow-file
	file  string
	mtime time.Time
	cfg   bool // ports come from the config file: authoritative, even when empty
}

func parsePorts(txt string) map[int]bool {
	m := map[int]bool{}
	for _, f := range strings.FieldsFunc(txt, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		if p, err := strconv.Atoi(f); err == nil && p > 0 && p < 65536 {
			m[p] = true
		}
	}
	return m
}

func isPortSep(r rune) bool {
	return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
}

// parseUDPPorts collects the `N/udp` tokens of a ports list (parsePorts skips them).
func parseUDPPorts(txt string) map[int]bool {
	m := map[int]bool{}
	for _, f := range strings.FieldsFunc(txt, isPortSep) {
		if s, ok := strings.CutSuffix(f, "/udp"); ok {
			if p, err := strconv.Atoi(s); err == nil && p > 0 && p < 65536 {
				m[p] = true
			}
		}
	}
	return m
}

func newAllow(list, file string) *allow {
	a := &allow{ports: parsePorts(list), udp: parseUDPPorts(list), file: file}
	if file != "" {
		a.reload()
		go func() {
			for range time.Tick(3 * time.Second) {
				a.reload()
			}
		}()
	}
	return a
}

func (a *allow) reload() {
	st, err := os.Stat(a.file)
	if err != nil || st.ModTime().Equal(a.mtime) {
		return
	}
	b, err := os.ReadFile(a.file)
	if err != nil {
		return
	}
	m, um := parsePorts(string(b)), parseUDPPorts(string(b))
	a.mu.Lock()
	a.ports, a.udp, a.mtime = m, um, st.ModTime()
	a.mu.Unlock()
	log.Printf("allowed target ports: %d", len(m))
}

// setPorts installs the config file's tcp ports as the (authoritative) allowlist.
func (a *allow) setPorts(ports []int) {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	a.mu.Lock()
	a.ports, a.cfg = m, true
	a.mu.Unlock()
	log.Printf("allowed target ports: %d", len(m))
}

// setUDPPorts installs the config file's udp ports (call after setPorts, which marks the list authoritative).
func (a *allow) setUDPPorts(ports []int) {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	a.mu.Lock()
	a.udp = m
	a.mu.Unlock()
	log.Printf("allowed udp target ports: %d", len(m))
}

// udpOK is ok for datagram flows: with any allowlist only listed /udp ports pass (a tcp-only list allows no udp).
func (a *allow) udpOK(port, lo, hi int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file != "" || a.cfg || len(a.ports) > 0 || len(a.udp) > 0 {
		return a.udp[port]
	}
	return port >= lo && port <= hi
}

func (a *allow) ok(port, lo, hi int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file != "" || a.cfg || len(a.ports) > 0 { // a file is authoritative, even when empty
		return a.ports[port]
	}
	return port >= lo && port <= hi
}

var debugOn bool

func dbg(f string, a ...any) {
	if debugOn {
		log.Printf(f, a...)
	}
}

// side is "c" or "s" for the process (stats key); set before any traffic.
var side = "c"

// bridge pipes c <-> st counting into ps; server = c is the target service, so c->st is the "down" direction.
func bridge(c net.Conn, st *wat.Stream, tag string, ps *portStat, server bool) {
	t0 := time.Now()
	var up, down int64
	var upErr, downErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := ps.copy(st, c, !server)
		up, upErr = n, err
		if err != nil {
			ps.errs.Add(1)
			st.Reset()
			return
		}
		st.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, err := ps.copy(c, st, server)
		down, downErr = n, err
		if tc, ok := c.(*net.TCPConn); ok && err == nil {
			tc.CloseWrite()
		} else if err != nil {
			c.Close()
		}
	}()
	wg.Wait()
	c.Close()
	dbg("%s done in %v: tcp->stream %d B (%v), stream->tcp %d B (%v)", tag, time.Since(t0).Round(time.Millisecond), up, upErr, down, downErr)
}

type clientJSON struct {
	IP      string `json:"ip"`
	Carrier string `json:"carrier"`
	AgeMS   int64  `json:"age_ms"`
}

// clientsJSON is the /stats "clients" list (server only): one row per live client session.
func clientsJSON(list []wat.ClientInfo) []clientJSON {
	out := make([]clientJSON, 0, len(list))
	for _, c := range list {
		out = append(out, clientJSON{c.IP, c.Carrier, c.Age.Milliseconds()})
	}
	return out
}
