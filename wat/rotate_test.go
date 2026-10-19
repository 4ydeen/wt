package wat

import (
	"testing"
	"time"
)

// TestRollRotateJitterBounds: the churn budget stays inside the ±40 % time / ±25 % count windows and above
// the floors, so a bad roll can never hot-loop the redialer nor synchronize the pool.
func TestRollRotateJitterBounds(t *testing.T) {
	base := time.Hour
	now := time.Now()
	for i := 0; i < 500; i++ {
		b := rollRotate(base, 4<<20) // 4 MB: above the 1 MB floor, so the jitter window is visible
		d := b.at.Sub(now)
		if d < 30*time.Minute || d > 90*time.Minute {
			t.Fatalf("roll %d: %v outside the 36..84 min jitter window", i, d)
		}
		if b.bytes < 3<<20 || b.bytes > 5<<20 {
			t.Fatalf("roll %d: %d bytes outside the 3..5 MB jitter window", i, b.bytes)
		}
	}
	// floors
	small := rollRotate(time.Second, 1)
	if small.at.Sub(now) < 10*time.Second {
		t.Fatalf("time floor not applied: %v", small.at.Sub(now))
	}
	if small.bytes < 1<<20 {
		t.Fatalf("byte floor not applied: %d", small.bytes)
	}
	// off switches
	off := rollRotate(0, 0)
	if !off.at.IsZero() || off.bytes != 0 {
		t.Fatalf("zero base did not disable the budget: %+v", off)
	}
}

// TestRotateDueSemantics: a connection recycles when EITHER axis of its budget is hit, and not before.
func TestRotateDueSemantics(t *testing.T) {
	pc := newPoolConn(nil)
	defer func() { if pc.c != nil { pc.c.Close() } }()
	now := time.Now()
	// no budget: never due
	if pc.rotateDue(now) {
		t.Fatal("no budget: reported due")
	}
	// time axis: past the timestamp => due
	b := rotateBudget{at: now.Add(-time.Second), bytes: 0}
	pc.rot.Store(&b)
	if !pc.rotateDue(now) {
		t.Fatal("past the time budget: not reported due")
	}
	// time axis: still inside => not due
	b.at = now.Add(time.Hour)
	pc.rot.Store(&b)
	if pc.rotateDue(now) {
		t.Fatal("inside the time budget: reported due")
	}
	// count axis: tx over the budget => due
	b.at = now.Add(time.Hour)
	b.bytes = 10
	pc.rot.Store(&b)
	pc.tx.Store(10)
	if !pc.rotateDue(now) {
		t.Fatal("tx hit the count budget: not reported due")
	}
	pc.tx.Store(9)
	if pc.rotateDue(now) {
		t.Fatal("tx under the count budget: reported due")
	}
}
