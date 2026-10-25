package wat

import (
	"testing"
)

// TestFilterProfileDefaults: before any probe runs, FilterProfileNow reports the zero value (no probe ran, Mode empty).
func TestFilterProfileDefaults(t *testing.T) {
	p := FilterProfileNow()
	if p.Mode != "" || p.Probed {
		t.Fatalf("default profile = %+v, want zero value", p)
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

// TestProbeFillerShape: the filler is probeBytes or more and starts like the carrier's own first bytes.
func TestProbeFillerShape(t *testing.T) {
	tls := probeFiller("tls", "mci.ir")
	if len(tls) < probeBytes || tls[0] != 0x16 || tls[5] != 1 {
		t.Fatalf("tls filler starts % x", tls[:6])
	}
	if sni, err := parseSNIOf(tls[:5+int(tls[3])<<8|int(tls[4])]); err != nil || sni != "mci.ir" {
		t.Fatalf("tls filler SNI %q, %v", sni, err)
	}
	if ws := string(probeFiller("ws", "a.example")[:33]); ws != "GET / HTTP/1.1\r\nHost: a.example\r\n" {
		t.Fatalf("ws filler starts %q", ws)
	}
	if tcp := probeFiller("tcp", ""); tcp[0] != 0 || isMimicPrefix(tcp[:8]) {
		t.Fatal("tcp filler id looks like a mimic hello")
	}
}
