package wat

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A small RFC 6455 implementation, just enough to carry the pool's byte stream through a CDN: binary frames only,
// client frames masked, ping answered, close honoured. wsConn is a net.Conn whose Write is one binary frame and whose
// Read walks the payload of incoming data frames, so the tcp pool runs on it unchanged.

const (
	wsGUID     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsMaxFrame = 4 << 20
)

type wsConn struct {
	net.Conn
	br     *bufio.Reader
	client bool
	wmu    sync.Mutex
	left   int64 // payload bytes still unread in the current data frame
	masked bool
	key    [4]byte
	kpos   int
	once   sync.Once
}

func newWSConn(c net.Conn, br *bufio.Reader, client bool) *wsConn {
	return &wsConn{Conn: c, br: br, client: client}
}

func (w *wsConn) writeFrame(op byte, p []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op
	n := 2
	switch l := len(p); {
	case l < 126:
		hdr[1] = byte(l)
	case l < 1<<16:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	buf := make([]byte, n+4+len(p))
	copy(buf, hdr[:n])
	body := buf[n:]
	if w.client {
		buf[1] |= 0x80
		var k [4]byte
		crand.Read(k[:])
		copy(body, k[:])
		body = body[4:]
		for i, b := range p {
			body[i] = b ^ k[i&3]
		}
		buf = buf[:n+4+len(p)]
	} else {
		copy(body, p)
		buf = buf[:n+len(p)]
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_, err := w.Conn.Write(buf)
	return err
}

func (w *wsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.writeFrame(2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// nextFrame reads frame headers until a data frame with payload starts; control frames are handled on the way.
func (w *wsConn) nextFrame() error {
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return err
		}
		op, masked, l := h[0]&0x0f, h[1]&0x80 != 0, int64(h[1]&0x7f)
		switch l {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return err
			}
			l = int64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return err
			}
			u := binary.BigEndian.Uint64(b[:])
			if u > wsMaxFrame {
				return errors.New("ws: frame too large")
			}
			l = int64(u)
		}
		if l > wsMaxFrame || (op >= 8 && l > 125) {
			return errors.New("ws: bad frame size")
		}
		var key [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, key[:]); err != nil {
				return err
			}
		}
		if op == 0 || op == 1 || op == 2 { // continuation/text/binary: all payload to the stream
			if l == 0 {
				continue
			}
			w.left, w.masked, w.key, w.kpos = l, masked, key, 0
			return nil
		}
		pl := make([]byte, l)
		if _, err := io.ReadFull(w.br, pl); err != nil {
			return err
		}
		if masked {
			for i := range pl {
				pl[i] ^= key[i&3]
			}
		}
		switch op {
		case 8:
			w.writeFrame(8, pl)
			return io.EOF
		case 9:
			if err := w.writeFrame(10, pl); err != nil {
				return err
			}
		case 10: // pong
		default:
			return fmt.Errorf("ws: unknown opcode %d", op)
		}
	}
}

func (w *wsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.left == 0 {
		if err := w.nextFrame(); err != nil {
			return 0, err
		}
	}
	if int64(len(p)) > w.left {
		p = p[:w.left]
	}
	n, err := w.br.Read(p)
	if w.masked {
		for i := 0; i < n; i++ {
			p[i] ^= w.key[(w.kpos+i)&3]
		}
		w.kpos += n
	}
	w.left -= int64(n)
	return n, err
}

func (w *wsConn) Close() error {
	w.once.Do(func() {
		w.Conn.SetWriteDeadline(time.Now().Add(time.Second))
		w.writeFrame(8, []byte{0x03, 0xe8}) // 1000 normal closure, best effort
	})
	return w.Conn.Close()
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsClientHandshake upgrades an established connection. host is the Host header, headers are extra request headers.
func wsClientHandshake(ctx context.Context, c net.Conn, host, path string, headers map[string]string) (*wsConn, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
		defer c.SetDeadline(time.Time{})
	}
	var kb [16]byte
	crand.Read(kb[:])
	key := base64.StdEncoding.EncodeToString(kb[:])
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", path, host, key)
	for k, v := range headers {
		if strings.ContainsAny(k+v, "\r\n") {
			return nil, errors.New("ws: bad header")
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(c, sb.String()); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, poolBufSize)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, fmt.Errorf("ws: handshake refused (%s)", resp.Status)
	}
	return newWSConn(c, br, true), nil
}

// wsServerUpgrade hijacks r into a websocket; false means "not a websocket request" and nothing was written.
func wsServerUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, bool) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if r.Method != "GET" || key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, false
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, false
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, false
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(key))
	c.SetDeadline(time.Time{})
	if err != nil {
		c.Close()
		return nil, true
	}
	return newWSConn(c, rw.Reader, false), true
}
