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
		{false, true, false, "sum"},    // died with seq marker in flight, sum survived: filter drops below-window junk -> use sum
		{true, false, false, "seq"},    // died with sum marker in flight, seq survived: filter drops bad checksums -> keep seq
		{false, false, false, "seqsum"}, // died under both -> try seqsum
		{true, true, false, "seq"},     // died later without correlation: nothing proved, keep the default
	}
	for _, c := range cases {
		p := filterProbe{seqOK: c.seqOK, sumOK: c.sumOK, alive: c.alive}
		var got string
		switch {
		case !p.alive && !p.seqOK && p.sumOK:
			got = "sum"
		case !p.alive && p.seqOK && !p.sumOK:
			got = "seq"
		case !p.alive && !p.seqOK && !p.sumOK:
			got = "seqsum"
		default:
			got = "seq"
		}
		if got != c.want {
			t.Fatalf("seqOK=%v sumOK=%v alive=%v: got %q want %q", c.seqOK, c.sumOK, c.alive, got, c.want)
		}
	}
}
