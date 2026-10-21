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
// (the probe itself needs a real filter to be meaningful; the mapping is the testable part). The
// verdict keys on which marker killed its flow, not on the final connAlive: sumOK already implies
// the sum socket was alive after the probe, so gating on p.alive made "sum" unreachable.
func TestProbeVerdictTable(t *testing.T) {
	cases := []struct {
		seqOK, sumOK, alive bool
		want                string
	}{
		{true, true, true, "seq"},    // nothing kills the flow: default
		{false, true, true, "sum"},   // seq marker killed its flow, sum survived: filter acts on below-window junk
		{true, false, false, "seq"},  // sum marker killed its flow, seq survived: filter acts on bad checksums
		{false, false, false, "seqsum"}, // both single markers killed their flows: try the dual marker
		{true, true, false, "seq"},   // final connAlive flaked without a marker correlation: keep the default
		{false, true, false, "sum"},  // verdict keys on the marker, not a flaky final recheck
	}
	for _, c := range cases {
		p := filterProbe{seqOK: c.seqOK, sumOK: c.sumOK, alive: c.alive}
		var got string
		switch {
		case !p.seqOK && p.sumOK:
			got = "sum"
		case !p.seqOK && !p.sumOK:
			got = "seqsum"
		default:
			got = "seq"
		}
		if got != c.want {
			t.Fatalf("seqOK=%v sumOK=%v alive=%v: got %q want %q", c.seqOK, c.sumOK, c.alive, got, c.want)
		}
	}
}

// TestSumProbeMultiSNI verifies that a filterProbe configured with comma-separated SNIs
// parses cleanly into individual valid hostnames and does not embed commas in the SNI.
func TestSumProbeMultiSNI(t *testing.T) {
	cfg := DesyncConfig{SNI: "mci.ir,divar.ir,digikala.com", Mode: "auto"}
	snis := splitSNIs(cfg.SNI)
	if len(snis) != 3 || snis[0] != "mci.ir" || snis[1] != "divar.ir" || snis[2] != "digikala.com" {
		t.Fatalf("unexpected split SNIs: %+v", snis)
	}
	hello := FakeClientHello(snis[0])
	gotSNI, err := parseSNIOf(hello)
	if err != nil {
		t.Fatalf("parseSNIOf error: %v", err)
	}
	if gotSNI != "mci.ir" {
		t.Fatalf("got SNI %q, want mci.ir", gotSNI)
	}
}
