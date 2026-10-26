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
	for _, k := range []string{"user-agent", "origin", "accept-language", "sec-websocket-key", "upgrade", "x-extra"} {
		if seen[k] != 1 {
			t.Fatalf("header %s sent %d times, want 1 (%q)", k, seen[k], lines)
		}
	}
}
