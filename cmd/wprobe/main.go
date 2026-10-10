// wprobe: measures what the Iran<->Kharej ICMP path really allows (reply/request ratio, loss vs rate and size,
// loss vs ident count). server mode runs on Kharej (the kernel ignores echo, so it writes its own replies),
// client mode runs on Iran. Packets carry magic "WPRB" and idents >= 0xC000 so other ICMP software ignores them.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	magic    = "WPRB"
	identMin = 0xC000
	hdrLen   = 4 + 1 + 1 + 2 + 4 + 8 // magic, k, variant, size, seq, sent ns
)

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

func pkt(typ byte, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:], csum(b))
	return b
}

func payload(k, variant byte, size int, seq uint32) []byte {
	if size < hdrLen {
		size = hdrLen
	}
	p := make([]byte, size)
	copy(p, magic)
	p[4], p[5] = k, variant
	binary.BigEndian.PutUint16(p[6:], uint16(size))
	binary.BigEndian.PutUint32(p[8:], seq)
	binary.BigEndian.PutUint64(p[12:], uint64(time.Now().UnixNano()))
	return p
}

func listen() net.PacketConn {
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("listen:", err)
		os.Exit(1)
	}
	return c
}

func server(dur time.Duration) {
	c := listen()
	defer c.Close()
	end := time.Now().Add(dur)
	buf := make([]byte, 2048)
	var in, out uint64
	for time.Now().Before(end) {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := c.ReadFrom(buf)
		if err != nil || n < 8+hdrLen || buf[0] != 8 || string(buf[8:12]) != magic {
			continue
		}
		id := binary.BigEndian.Uint16(buf[4:])
		if id < identMin {
			continue
		}
		seq := binary.BigEndian.Uint16(buf[6:])
		k, variant := buf[8+4], buf[8+5]
		size := int(binary.BigEndian.Uint16(buf[8+6:]))
		pseq := binary.BigEndian.Uint32(buf[8+8:])
		in++
		if variant == 3 { // upload-only test: count it, send nothing back
			continue
		}
		if k == 0 {
			k = 1
		}
		for j := byte(0); j < k; j++ {
			rs := seq
			switch variant {
			case 1: // replies carry different seq numbers than the request
				rs = seq + 1000 + uint16(j)
			case 2: // one same-seq reply, the rest new seq
				if j > 0 {
					rs = seq + 2000 + uint16(j)
				}
			}
			p := payload(k, variant, size, pseq)
			copy(p[12:20], buf[8+12:8+20])
			p[5] = j
			c.WriteTo(pkt(0, id, rs, p), addr)
			out++
		}
	}
	fmt.Printf("server done in=%d out=%d\n", in, out)
}

type result struct {
	sent, got   uint64
	rtts        []time.Duration
	mu          sync.Mutex
	extra, uniq uint64
}

// run sends reqPps requests/s of payload size on nIdent idents for dur and counts the replies.
func run(c net.PacketConn, dst net.Addr, reqPps, size, nIdent int, k, variant byte, dur time.Duration, tag string) {
	r := &result{}
	seen := sync.Map{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := c.ReadFrom(buf)
			if err != nil || n < 8+hdrLen || buf[0] != 0 || string(buf[8:12]) != magic {
				continue
			}
			id := binary.BigEndian.Uint16(buf[4:])
			if id < identMin {
				continue
			}
			sent := int64(binary.BigEndian.Uint64(buf[8+12:]))
			atomic.AddUint64(&r.got, 1)
			key := uint64(id)<<48 | uint64(binary.BigEndian.Uint32(buf[8+8:]))<<8 | uint64(buf[8+5]&0)
			_, dup := seen.LoadOrStore(key, true)
			if !dup {
				atomic.AddUint64(&r.uniq, 1)
			}
			r.mu.Lock()
			if len(r.rtts) < 200000 {
				r.rtts = append(r.rtts, time.Duration(time.Now().UnixNano()-sent))
			}
			r.mu.Unlock()
		}
	}()
	start := time.Now()
	tick := time.NewTicker(time.Millisecond)
	var seq uint32
	var sentN uint64
	for t := range tick.C {
		el := t.Sub(start)
		if el > dur {
			break
		}
		want := uint64(float64(reqPps) * el.Seconds())
		for sentN < want {
			id := uint16(identMin + int(seq)%nIdent)
			c.WriteTo(pkt(8, id, uint16(seq), payload(k, variant, size, seq)), dst)
			seq++
			sentN++
		}
	}
	tick.Stop()
	time.Sleep(1200 * time.Millisecond)
	close(stop)
	wg.Wait()
	r.mu.Lock()
	sort.Slice(r.rtts, func(i, j int) bool { return r.rtts[i] < r.rtts[j] })
	p := func(q float64) float64 {
		if len(r.rtts) == 0 {
			return 0
		}
		return float64(r.rtts[int(q*float64(len(r.rtts)-1))]) / 1e6
	}
	exp := sentN * uint64(max(int(k), 1))
	fmt.Printf("%-22s req/s=%-6d size=%-4d idents=%-3d k=%d v=%d sent=%-6d got=%-6d (%.1f%% of expected %d) rtt p50=%.1f p99=%.1f ms\n",
		tag, reqPps, size, nIdent, k, variant, sentN, r.got, 100*float64(r.got)/float64(max64(exp, 1)), exp, p(.5), p(.99))
	r.mu.Unlock()
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func client(dstIP string, quick bool) {
	c := listen()
	defer c.Close()
	dst := &net.IPAddr{IP: net.ParseIP(dstIP)}
	d := 6 * time.Second
	if quick {
		d = 3 * time.Second
	}
	fmt.Println("== 1. reply:request ratio (50 req/s, 600 B)")
	run(c, dst, 50, 600, 1, 1, 0, d, "1 reply same seq")
	run(c, dst, 50, 600, 1, 2, 0, d, "2 replies same seq")
	run(c, dst, 50, 600, 1, 4, 0, d, "4 replies same seq")
	run(c, dst, 50, 600, 1, 1, 1, d, "1 reply other seq")
	run(c, dst, 50, 600, 1, 4, 1, d, "4 replies other seq")
	run(c, dst, 50, 600, 1, 4, 2, d, "1 same + 3 other seq")
	fmt.Println("== 2. loss vs request rate (1 reply, 600 B, 8 idents)")
	for _, r := range []int{500, 1000, 2000, 4000, 6000, 8000, 12000} {
		run(c, dst, r, 600, 8, 1, 0, d, "rate")
	}
	fmt.Println("== 3. loss vs size (2000 req/s, 8 idents)")
	for _, s := range []int{64, 200, 400, 560, 640} {
		run(c, dst, 2000, s, 8, 1, 0, d, "size")
	}
	fmt.Println("== 4. loss vs ident count (4000 req/s, 600 B)")
	for _, n := range []int{1, 2, 8, 32, 128} {
		run(c, dst, 4000, 600, n, 1, 0, d, "idents")
	}
}

func custom(dstIP, steps string) {
	c := listen()
	defer c.Close()
	dst := &net.IPAddr{IP: net.ParseIP(dstIP)}
	for _, st := range strings.Split(steps, ",") {
		f := strings.Split(st, ":")
		a := make([]int, 6)
		a[5] = 4
		for i := range f {
			a[i], _ = strconv.Atoi(f[i])
		}
		run(c, dst, a[0], a[1], a[2], byte(a[3]), byte(a[4]), time.Duration(a[5])*time.Second, "custom")
	}
}

func main() {
	mode := flag.String("mode", "", "server|client")
	dst := flag.String("dst", "", "peer ip (client)")
	dur := flag.Duration("dur", 10*time.Minute, "server lifetime")
	quick := flag.Bool("quick", false, "3 s per step")
	steps := flag.String("steps", "", "custom client steps rate:size:idents:k:variant[:secs],...")
	flag.Parse()
	switch *mode {
	case "server":
		server(*dur)
	case "client":
		if *steps != "" {
			custom(*dst, *steps)
			return
		}
		client(*dst, *quick)
	default:
		fmt.Println("usage: wprobe -mode server|client")
	}
}
