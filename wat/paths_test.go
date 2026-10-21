package wat

import (
	"testing"
	"time"
)

func TestMergeProfiles(t *testing.T) {
	// Empty slice returns default non-zero profile
	empty := mergeProfiles(nil)
	if empty.MTU == 0 || empty.MaxMTU == 0 || empty.InitBps == 0 {
		t.Fatalf("empty mergeProfiles returned zero profile: %+v", empty)
	}

	p1 := Profile{Reliable: true, MTU: 4096, MaxMTU: 16384, InitBps: 8e6}
	p2 := Profile{Reliable: false, MTU: 1400, MaxMTU: 1400, InitBps: 1.5e6}

	merged := mergeProfiles([]Profile{p1, p2})
	if merged.Reliable {
		t.Error("expected unreliable when one carrier is unreliable")
	}
	if merged.MTU != 1400 {
		t.Errorf("MTU: got %d, want 1400", merged.MTU)
	}
	if merged.MaxMTU != 1400 {
		t.Errorf("MaxMTU: got %d, want 1400", merged.MaxMTU)
	}
	if merged.InitBps != 1.5e6 {
		t.Errorf("InitBps: got %v, want 1.5e6", merged.InitBps)
	}
}

func TestPathTimingsNorm(t *testing.T) {
	tm := PathTimings{
		ProbeFirst: 10 * time.Second,
		ProbeMax:   5 * time.Second,
	}.norm()

	if tm.ProbeFirst > tm.ProbeMax {
		t.Errorf("ProbeFirst (%v) > ProbeMax (%v)", tm.ProbeFirst, tm.ProbeMax)
	}
	if tm.Silence <= 0 || tm.Ramp <= 0 || tm.IdleProbe <= 0 {
		t.Errorf("zero defaults not set: %+v", tm)
	}
}
