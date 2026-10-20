package wat

import (
	"testing"
	"time"
)

// TestGovernorLearnsCeiling: sustained bulk with a stable base RTT arms the governor; a base-RTT jump (the
// reroute signature) sets a ceiling at 80 % of the pre-jump rate, held for govHold; quiet windows creep it
// back up and release it at 1.25x the trigger rate.
func TestGovernorLearnsCeiling(t *testing.T) {
	old := governorOn.Load()
	governorOn.Store(true)
	defer governorOn.Store(old)
	now := time.Now()
	g := &govState{}
	rate := 40e6 // 40 MB/s bulk
	// 4 stable windows at base RTT 40 ms: armed, no ceiling yet
	for w := 0; w < 4; w++ {
		for i := 0; i < 10; i++ {
			g.govSample(40*time.Millisecond, rate, now)
			now = now.Add(200 * time.Millisecond)
		}
	}
	if !g.armed {
		t.Fatalf("governor never armed after 4 stable windows")
	}
	if g.ceiling != 0 {
		t.Fatalf("ceiling set without a signature: %f", g.ceiling)
	}
	// the signature: base RTT jumps to 76 ms (the field's 40 -> 76)
	g.govSample(76*time.Millisecond, rate, now)
	now = now.Add(200 * time.Millisecond)
	g.govSample(76*time.Millisecond, rate, now) // close the window with the jump
	if g.ceiling == 0 {
		t.Fatalf("no ceiling learned from the base-RTT jump")
	}
	want := rate * govCut
	if g.ceiling < want*0.99 || g.ceiling > want*1.01 {
		t.Fatalf("ceiling %f, want ~%f (80%% of the pre-jump rate)", g.ceiling, want)
	}
	if !g.holdUntil.After(now) {
		t.Fatalf("no hold after the signature")
	}
	// holding: samples inside the hold neither raise nor lower it
	g.govSample(76*time.Millisecond, 80e6, now)
	if g.ceiling < want*0.99 {
		t.Fatalf("hold changed the ceiling")
	}
	// recovery: after the hold, quiet windows at the old base creep the ceiling up and release it
	now = g.holdUntil.Add(time.Second)
	for w := 0; w < 40; w++ {
		g.govSample(40*time.Millisecond, g.ceiling*0.5, now)
		now = now.Add(200 * time.Millisecond)
	}
	if g.ceiling != 0 {
		t.Fatalf("ceiling never released after quiet recovery: %f", g.ceiling)
	}
}

// TestGovernorOffByDefault: without SetGovernor(true), nothing is learned and nothing caps the rate.
func TestGovernorOffByDefault(t *testing.T) {
	if governorOn.Load() {
		t.Skip("governor enabled by another test; run alone")
	}
	now := time.Now()
	g := &govState{}
	for i := 0; i < 100; i++ {
		g.govSample(40*time.Millisecond, 50e6, now)
		now = now.Add(200 * time.Millisecond)
	}
	g.govSample(200*time.Millisecond, 50e6, now) // a jump
	if g.ceiling != 0 || g.armed {
		t.Fatalf("governor learned while disabled (ceiling %f armed %v)", g.ceiling, g.armed)
	}
}
