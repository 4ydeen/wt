package wat

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CDN-compatible carriers: ws/wss (WebSocket), h2/h2c (one full-duplex HTTP/2 POST per pool connection) and grpc
// (the same with gun-style gRPC framing). Each is only a stream transport for the tcp pool: the client side is a
// PoolDialFunc, the server side a net.Listener that hands accepted streams to the pool server, so queueing, drop,
// redial and pool grouping are the tcp pool's. HTTP/2 uses the standard library's built-in implementation (no new
// module dependency).

// HTTPClientOptions configures the ws/h2/grpc client carriers.
type HTTPClientOptions struct {
	Path    string            // request path (grpc: the service name, the request goes to <Path>/Tun)
	Host    string            // Host header / :authority (default: the peer address)
	Headers map[string]string // extra request headers
	Secure  bool              // TLS (wss, h2, grpc over TLS); false = ws, h2c
	TLS     TLSClientOptions
}

// HTTPServerOptions configures the ws/h2/grpc server carriers.
type HTTPServerOptions struct {
	Path     string
	Secure   bool   // serve TLS
	CertFile string // empty with KeyFile empty = self-signed in memory
	KeyFile  string
}

func normPath(p string) string {
	if p == "" {
		p = "/wat"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func (o HTTPClientOptions) host(peer string) string {
	if o.Host != "" {
		return o.Host
	}
	return peer
}

func (o HTTPClientOptions) tlsConfig(proto string) *tls.Config {
	t := o.TLS
	if t.ServerName == "" && o.Host != "" {
		t.ServerName, _, _ = strings.Cut(o.Host, ":")
	}
	cfg := t.config()
	cfg.NextProtos = []string{proto}
	return cfg
}

// ---------------------------------------------------------------- websocket

// NewWSPoolClient is the ws (o.Secure false) or wss pool client.
func NewWSPoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	if _, _, err := net.SplitHostPort(peer); err != nil {
		return nil, err
	}
	path, host := normPath(o.Path), o.host(peer)
	d := net.Dialer{Timeout: 5 * time.Second}
	return newPoolClient(func(ctx context.Context) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp", peer)
		if err != nil {
			return nil, err
		}
		if o.Secure {
			tc := tls.Client(c, o.tlsConfig("http/1.1"))
			if err = tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			c = tc
		}
		w, err := wsClientHandshake(ctx, c, host, path, o.Headers)
		if err != nil {
			c.Close()
			return nil, err
		}
		return w, nil
	}, conns)
}

// NewWSPoolServer serves the pool over WebSocket on o.Path; any other request gets a plain 404.
func NewWSPoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	path := normPath(o.Path)
	return newHTTPPoolServer(addr, o, func(l *httpListener) http.Handler {
		return pathMux(path, func(w http.ResponseWriter, r *http.Request) bool {
			c, ok := wsServerUpgrade(w, r)
			if c != nil {
				l.push(c)
			}
			return ok
		})
	})
}

// ---------------------------------------------------------------- listener that serves an http.Server

// httpListener is the net.Listener the pool server accepts from: HTTP handlers push finished streams into it.
type httpListener struct {
	ch   chan net.Conn
	done chan struct{}
	addr net.Addr
	srv  *http.Server
	wg   sync.WaitGroup
	once sync.Once
}

func (l *httpListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	case <-time.After(5 * time.Second):
		c.Close()
	}
}

func (l *httpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *httpListener) Addr() net.Addr { return l.addr }

func (l *httpListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.srv.Close()
		l.wg.Wait()
	})
	return nil
}

// pathMux answers path with h (which returns false when the request is not ours) and everything else, and anything
// h refuses, with a bare 404 like an ordinary web server.
func pathMux(path string, h func(http.ResponseWriter, *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && h(w, r) {
			return
		}
		http.NotFound(w, r)
	})
}

func newHTTPPoolServer(addr string, o HTTPServerOptions, mk func(*httpListener) http.Handler) (*TCPPoolServer, error) {
	var cert tls.Certificate
	var err error
	if o.Secure {
		if o.CertFile != "" || o.KeyFile != "" {
			cert, err = tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		} else {
			cert, err = SelfSignedCert()
		}
		if err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &httpListener{ch: make(chan net.Conn, 64), done: make(chan struct{}), addr: ln.Addr()}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetHTTP2(o.Secure)
	protos.SetUnencryptedHTTP2(!o.Secure)
	l.srv = &http.Server{Handler: mk(l), ReadHeaderTimeout: 10 * time.Second, Protocols: &protos,
		ErrorLog: log.New(io.Discard, "", 0)}
	var serve func() error
	if o.Secure {
		l.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		serve = func() error { return l.srv.ServeTLS(ln, "", "") }
	} else {
		serve = func() error { return l.srv.Serve(ln) }
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		serve()
	}()
	return newPoolServer(l), nil
}

// ---------------------------------------------------------------- h2 / grpc stream

type h2Addr struct{ s string }

func (a h2Addr) Network() string { return "h2" }
func (a h2Addr) String() string  { return a.s }

// h2Conn adapts one HTTP/2 request/response pair to a net.Conn: Read is the peer's body, Write the own body.
type h2Conn struct {
	r       io.Reader
	w       io.Writer
	flush   func()
	closeFn func()
	mu      sync.Mutex // serialises Write against the handler returning
	closed  atomic.Bool
	done    chan struct{}
	local   net.Addr
	remote  net.Addr
	timer   atomic.Pointer[time.Timer]
}

func newH2Conn(r io.Reader, w io.Writer, flush, closeFn func(), local, remote net.Addr) *h2Conn {
	return &h2Conn{r: r, w: w, flush: flush, closeFn: closeFn, done: make(chan struct{}), local: local, remote: remote}
}

func (c *h2Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *h2Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.w.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *h2Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.done)
		if c.closeFn != nil {
			c.closeFn()
		}
	}
	return nil
}

func (c *h2Conn) LocalAddr() net.Addr  { return c.local }
func (c *h2Conn) RemoteAddr() net.Addr { return c.remote }
func (c *h2Conn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline only supports what the pool needs: a bound on the hello. Expiry closes the stream.
func (c *h2Conn) SetReadDeadline(t time.Time) error {
	if old := c.timer.Swap(nil); old != nil {
		old.Stop()
	}
	if !t.IsZero() {
		c.timer.Store(time.AfterFunc(time.Until(t), func() { c.Close() }))
	}
	return nil
}
func (c *h2Conn) SetWriteDeadline(time.Time) error { return nil }

// wait blocks the server handler until the stream is closed (locally or by the peer), then waits briefly for an
// in-flight Write so the ResponseWriter is never used after the handler returns.
func (c *h2Conn) wait(ctx context.Context) {
	select {
	case <-c.done:
	case <-ctx.Done():
		c.Close()
	}
	locked := make(chan struct{})
	go func() { c.mu.Lock(); c.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
	}
}

// ---------------------------------------------------------------- h2 client / server

func newH2Client(peer string, conns int, o HTTPClientOptions, grpc bool) (*TCPPoolClient, error) {
	if _, _, err := net.SplitHostPort(peer); err != nil {
		return nil, err
	}
	path := normPath(o.Path)
	if grpc {
		path += "/Tun"
	}
	scheme := "http"
	if o.Secure {
		scheme = "https"
	}
	url, host := scheme+"://"+peer+path, o.host(peer)
	return newPoolClient(func(ctx context.Context) (net.Conn, error) {
		var protos http.Protocols
		protos.SetHTTP2(o.Secure)
		protos.SetUnencryptedHTTP2(!o.Secure)
		tr := &http.Transport{Protocols: &protos, DisableKeepAlives: true, ForceAttemptHTTP2: true,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
		if o.Secure {
			tr.TLSClientConfig = o.tlsConfig("h2")
		}
		rctx, cancel := context.WithCancel(ctx)
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(rctx, "POST", url, pr)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Host, req.ContentLength = host, -1
		for k, v := range o.Headers {
			req.Header.Set(k, v)
		}
		if grpc {
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
		} else {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		t := time.AfterFunc(10*time.Second, cancel) // bounds the connect; headers arrive as soon as the server accepts
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if !t.Stop() && err == nil {
			err = context.DeadlineExceeded
		}
		if err == nil && resp.StatusCode != 200 {
			resp.Body.Close()
			err = errors.New("h2: server answered " + resp.Status)
		}
		if err != nil {
			cancel()
			pw.Close()
			tr.CloseIdleConnections()
			return nil, err
		}
		var rd io.Reader = resp.Body
		var wr io.Writer = pw
		c := newH2Conn(rd, wr, nil, func() {
			pw.CloseWithError(io.EOF)
			cancel()
			resp.Body.Close()
			tr.CloseIdleConnections()
		}, h2Addr{"client"}, h2Addr{peer})
		if grpc {
			return newGRPCConn(c), nil
		}
		return c, nil
	}, conns)
}

// NewH2PoolClient is the h2 (o.Secure) or h2c pool client: every pool connection is one POST on its own TCP connection.
func NewH2PoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	return newH2Client(peer, conns, o, false)
}

// NewGRPCPoolClient is NewH2PoolClient with gun-style gRPC framing on path <Path>/Tun.
func NewGRPCPoolClient(peer string, conns int, o HTTPClientOptions) (*TCPPoolClient, error) {
	return newH2Client(peer, conns, o, true)
}

func h2Server(addr string, o HTTPServerOptions, grpc bool) (*TCPPoolServer, error) {
	path := normPath(o.Path)
	if grpc {
		path += "/Tun"
	}
	return newHTTPPoolServer(addr, o, func(l *httpListener) http.Handler {
		return pathMux(path, func(w http.ResponseWriter, r *http.Request) bool {
			fl, ok := w.(http.Flusher)
			if !ok || r.Method != "POST" || r.ProtoMajor < 2 {
				return false
			}
			if grpc {
				if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
					return false
				}
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status")
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(200)
			fl.Flush()
			ra, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
			var rem net.Addr = h2Addr{r.RemoteAddr}
			if ra != nil {
				rem = ra
			}
			c := newH2Conn(r.Body, w, fl.Flush, nil, l.addr, rem)
			var sc net.Conn = c
			if grpc {
				sc = newGRPCConn(c)
			}
			l.push(sc)
			c.wait(r.Context())
			if grpc {
				w.Header().Set("Grpc-Status", "0")
			}
			return true
		})
	})
}

// NewH2PoolServer serves the pool over HTTP/2 POST streams on o.Path (h2c unless o.Secure).
func NewH2PoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	return h2Server(addr, o, false)
}

// NewGRPCPoolServer serves the pool as a gun-style gRPC service at <Path>/Tun.
func NewGRPCPoolServer(addr string, o HTTPServerOptions) (*TCPPoolServer, error) {
	return h2Server(addr, o, true)
}

// ---------------------------------------------------------------- grpc framing

const grpcMaxMsg = 1 << 20

// grpcConn wraps a net.Conn so Write emits gRPC messages (flag 0, uint32 length, protobuf field 1 = the bytes, as
// Xray's gun Hunk) and Read unwraps them.
type grpcConn struct {
	net.Conn
	br  *bufio.Reader
	rem []byte
	mu  sync.Mutex
}

func newGRPCConn(c net.Conn) *grpcConn {
	return &grpcConn{Conn: c, br: bufio.NewReaderSize(c, poolBufSize)}
}

func (g *grpcConn) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		var vb [binary.MaxVarintLen32]byte
		vl := binary.PutUvarint(vb[:], uint64(n))
		pb := 1 + vl + n
		buf := make([]byte, 0, 5+pb)
		buf = append(buf, 0)
		buf = binary.BigEndian.AppendUint32(buf, uint32(pb))
		buf = append(buf, 0x0a)
		buf = append(buf, vb[:vl]...)
		buf = append(buf, p[:n]...)
		g.mu.Lock()
		_, err := g.Conn.Write(buf)
		g.mu.Unlock()
		if err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}

func (g *grpcConn) Read(p []byte) (int, error) {
	for len(g.rem) == 0 {
		var h [5]byte
		if _, err := io.ReadFull(g.br, h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[1:])
		if h[0] != 0 || n > grpcMaxMsg {
			return 0, errors.New("grpc: bad message")
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(g.br, msg); err != nil {
			return 0, err
		}
		if len(msg) == 0 {
			continue
		}
		if msg[0] != 0x0a {
			return 0, errors.New("grpc: unexpected field")
		}
		l, vn := binary.Uvarint(msg[1:])
		if vn <= 0 || uint64(len(msg)-1-vn) != l {
			return 0, errors.New("grpc: bad hunk")
		}
		g.rem = msg[1+vn:]
	}
	n := copy(p, g.rem)
	g.rem = g.rem[n:]
	return n, nil
}
