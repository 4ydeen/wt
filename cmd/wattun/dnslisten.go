package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// dnsServfail constructs a minimal RFC 1035 Server Failure (RCODE 2) response for query.
func dnsServfail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81 // QR=1 (response), RD=1 (recursion desired)
	resp[3] = 0x82 // RA=1 (recursion available), RCODE=2 (server failure)
	// Zero out answer, authority, and additional counts; keep question count
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0
	return resp
}

// startDNSListener starts a local UDP DNS listener that forwards all queries through the tunnel's
// internal DNS relay (server target port 53). This allows client operating systems and applications
// to resolve external DNS records during severe censorship blackouts when domestic resolvers hijack UDP 53.
func startDNSListener(listenAddr string, getTun func() *tunnel, logf func(string, ...any)) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	if logf != nil {
		logf("dns-listen: listening on %s (forwarding queries via tunnel DNS relay)", listenAddr)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					if errors.Is(err, net.ErrClosed) {
						return
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			if n < 12 || n > 512 {
				continue
			}
			query := make([]byte, n)
			copy(query, buf[:n])

			go func(q []byte, from net.Addr) {
				tun := getTun()
				ans, err := dialDNSRelay(tun, q)
				if err != nil || len(ans) < 12 {
					if sf := dnsServfail(q); sf != nil {
						_, _ = pc.WriteTo(sf, from)
					}
					return
				}
				_, _ = pc.WriteTo(ans, from)
			}(query, src)
		}
	}()

	return &dnsListenerCloser{
		pc:   pc,
		done: done,
		wg:   &wg,
	}, nil
}

type dnsListenerCloser struct {
	pc   net.PacketConn
	done chan struct{}
	wg   *sync.WaitGroup
	once sync.Once
}

func (c *dnsListenerCloser) Close() error {
	c.once.Do(func() {
		close(c.done)
		_ = c.pc.Close()
		c.wg.Wait()
	})
	return nil
}
