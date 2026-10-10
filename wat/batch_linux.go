//go:build linux

package wat

import (
	"net"
	"os"
	"sync"

	"golang.org/x/net/ipv4"
)

// recvmmsg / sendmmsg through x/net/ipv4. Off unless WAT_BATCH=1 (plain ReadFrom / WriteTo, the
// behaviour before v1.6.0).

const (
	rxBatch = 32   // datagrams per recvmmsg
	rxBufSz = 2048 // fits the largest datagram of the raw-socket and UDP carriers (1400 + headers)
)

// WAT_BATCH: unset = on for the ICMP carrier, off for the others; "0" = off everywhere; anything else = on.
// ICMP default on since v1.8.0: on the real Iran<->Kharej path (2026-10-10) it raised one flow 15 -> 25 MB/s and cut
// CPU/MB from 0.043 to 0.026 (it had looked neutral on the veth bench, which has no per-packet path cost).
func batchDisabled() bool { return os.Getenv("WAT_BATCH") == "" || os.Getenv("WAT_BATCH") == "0" }

func icmpBatchDisabled() bool { return os.Getenv("WAT_BATCH") == "0" }

// mmsgRx reads up to rxBatch datagrams per system call and hands them out one by one.
type mmsgRx struct {
	pc   *ipv4.PacketConn
	msgs []ipv4.Message
	n, i int
}

func newMmsgRx(pc *ipv4.PacketConn) *mmsgRx {
	r := &mmsgRx{pc: pc, msgs: make([]ipv4.Message, rxBatch)}
	for i := range r.msgs {
		r.msgs[i].Buffers = [][]byte{make([]byte, rxBufSz)}
	}
	return r
}

// next returns the next datagram; it is valid until the next call that refills the batch.
func (r *mmsgRx) next() ([]byte, net.Addr, error) {
	for r.i >= r.n {
		n, err := r.pc.ReadBatch(r.msgs, 0)
		if err != nil {
			return nil, nil, err
		}
		r.n, r.i = n, 0
	}
	m := &r.msgs[r.i]
	r.i++
	return m.Buffers[0][:m.N], m.Addr, nil
}

// mmsgTx sends a burst with sendmmsg. Shared by every session of a server, hence the lock.
type mmsgTx struct {
	pc   *ipv4.PacketConn
	mu   sync.Mutex
	msgs []ipv4.Message
}

// write sends the messages built by fill (called under the lock with the reusable message slice).
func (t *mmsgTx) write(n int, dst net.Addr, set func(i int, m *ipv4.Message)) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.msgs) < n {
		t.msgs = append(t.msgs, ipv4.Message{Buffers: make([][]byte, 1)})
	}
	ms := t.msgs[:n]
	for i := range ms {
		ms[i].Addr = dst
		set(i, &ms[i])
	}
	var err error
	for len(ms) > 0 {
		var k int
		if k, err = t.pc.WriteBatch(ms, 0); err != nil || k <= 0 {
			break
		}
		ms = ms[k:]
	}
	for i := 0; i < n; i++ {
		t.msgs[i].Buffers[0] = nil
	}
	return err
}

// ---- UDP

type udpBatch struct {
	rx *mmsgRx
	tx mmsgTx
}

func newUDPBatch(c *net.UDPConn) *udpBatch {
	if batchDisabled() {
		return nil
	}
	pc := ipv4.NewPacketConn(c)
	return &udpBatch{rx: newMmsgRx(pc), tx: mmsgTx{pc: pc}}
}

func (b *udpBatch) recv() ([]byte, net.Addr, error) { return b.rx.next() }

// send writes the datagrams; dst is nil on a connected socket.
func (b *udpBatch) send(ps [][]byte, dst net.Addr) error {
	return b.tx.write(len(ps), dst, func(i int, m *ipv4.Message) { m.Buffers[0] = ps[i] })
}
