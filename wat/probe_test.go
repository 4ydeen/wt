package wat

import (
	"testing"
)

// TestFilterProfileDefaults: before any probe runs, FilterProfileNow reports the seq default with Probed=false.
func TestFilterProfileDefaults(t *testing.T) {
	p := FilterProfileNow()
	if p.Mode != "seq" || p.Probed {
		t.Fatalf("default profile = %+v, want {seq probed=false}", p)
	}
}

// TestProbeVerdictTable pins the verdict mapping of filterProbe.run against synthetic observations
// (the probe itself needs a real filter to be meaningful; the mapping is the testable part).
func TestProbeVerdictTable(t *testing.T) {
	cases := []struct {
		seqOK, sumOK, alive bool
		want                string
	}{
		{true, true, true, "seq"},      // nothing kills the flow: default
		{true, false, false, "sum"},    // died with the sum marker in flight: filter reads checksums
		{false, true, false, "seqsum"}, // died even with a seq marker alone: throw both
		{false, false, false, "seqsum"},
		{true, true, false, "seq"}, // died later without correlation: nothing proved, keep the default
	}
	for _, c := range cases {
		p := filterProbe{seqOK: c.seqOK, sumOK: c.sumOK, alive: c.alive}
		var got string
		switch {
		case !p.alive && p.seqOK && !p.sumOK:
			got = "sum"
		case !p.alive && !p.seqOK:
			got = "seqsum"
		default:
			got = "seq"
		}
		if got != c.want {
			t.Fatalf("seqOK=%v sumOK=%v alive=%v: got %q want %q", c.seqOK, c.sumOK, c.alive, got, c.want)
		}
	}
}
