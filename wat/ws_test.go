package wat

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestWSHandshakeLooksLikeABrowser: the upgrade request carries a browser's header set (User-Agent, Origin, ...) and
// a header the caller gives replaces the default of the same name instead of being sent twice (3.0.1).
func TestWSHandshakeLooksLikeABrowser(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	got := make(chan []string, 1)
	go func() {
		br := bufio.NewReader(srv)
		var lines []string
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			lines = append(lines, l)
		}
		got <- lines
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wsClientHandshake(ctx, cli, "cdn.example.com", "/api/1", true, map[string]string{"user-agent": "Custom/1", "X-Extra": "1"}) // the pipe closes: only the request matters
	lines := <-got
	if lines[0] != "GET /api/1 HTTP/1.1" || lines[1] != "Host: cdn.example.com" {
		t.Fatalf("request line / Host first, got %q", lines[:2])
	}
	seen := map[string]int{}
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, ": ")
		seen[strings.ToLower(k)]++
		if strings.EqualFold(k, "User-Agent") && v != "Custom/1" {
			t.Fatalf("the caller's User-Agent must win, got %q", v)
		}
	}
	for _, k := range []string{"user-agent", "origin", "accept-language", "sec-websocket-key", "upgrade", "sec-websocket-extensions", "x-extra"} {
		if seen[k] != 1 {
			t.Fatalf("header %s sent %d times, want 1 (%q)", k, seen[k], lines)
		}
	}
}

// TestWSHandshakeRefusesNegotiatedExtension: the request offers permessage-deflate, and a peer that accepts it is
// refused at the handshake rather than sending frames the reader cannot decode (3.0.2).
func TestWSHandshakeRefusesNegotiatedExtension(t *testing.T) {
	for _, ext := range []string{"", "permessage-deflate"} {
		cli, srv := net.Pipe()
		go func() {
			defer srv.Close()
			br := bufio.NewReader(srv)
			var key string
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimRight(l, "\r\n")
				if l == "" {
					break
				}
				if k, v, ok := strings.Cut(l, ": "); ok && strings.EqualFold(k, "Sec-WebSocket-Key") {
					key = v
				}
			}
			resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(key) + "\r\n"
			if ext != "" {
				resp += "Sec-WebSocket-Extensions: " + ext + "\r\n"
			}
			srv.Write([]byte(resp + "\r\n"))
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := wsClientHandshake(ctx, cli, "cdn.example.com", "/api/1", true, nil)
		cancel()
		cli.Close()
		if (ext == "") != (err == nil) {
			t.Fatalf("extension %q: err=%v", ext, err)
		}
	}
}
