package wat

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestReviveEngineVerification(t *testing.T) {
	psk := []byte("test-revive-psk-1234567890abcdef")
	var executedAction uint8
	var executedSrc net.Addr

	engine := NewReviveEngine(psk, func(act uint8, src net.Addr) {
		executedAction = act
		executedSrc = src
	})

	dummySrc := &net.IPAddr{IP: net.ParseIP("198.51.100.1")}
	knock, err := engine.BuildKnock(ReviveReloadListeners)
	if err != nil {
		t.Fatalf("BuildKnock failed: %v", err)
	}
	if len(knock) != 36 {
		t.Fatalf("expected 36 bytes knock, got %d", len(knock))
	}

	act, err := engine.VerifyKnock(knock, dummySrc)
	if err != nil {
		t.Fatalf("VerifyKnock failed: %v", err)
	}
	if act != ReviveReloadListeners {
		t.Fatalf("expected action 0x%02x, got 0x%02x", ReviveReloadListeners, act)
	}
	if executedAction != ReviveReloadListeners || executedSrc != dummySrc {
		t.Fatalf("callback not triggered correctly")
	}

	// Test Replay detection
	_, err = engine.VerifyKnock(knock, dummySrc)
	if err == nil || err.Error() != "revive: replay detected" {
		t.Fatalf("expected replay error, got %v", err)
	}

	// Test tampered tag
	tampered := append([]byte(nil), knock...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = engine.VerifyKnock(tampered, dummySrc)
	if err == nil {
		t.Fatalf("expected verification failure on tampered tag")
	}

	// Test wrong PSK
	wrongEngine := NewReviveEngine([]byte("different-psk-0000000000000000"), nil)
	freshKnock, _ := engine.BuildKnock(ReviveReverseCompanion)
	_, err = wrongEngine.VerifyKnock(freshKnock, dummySrc)
	if err == nil {
		t.Fatalf("expected verification failure with wrong PSK")
	}

	// Test freshness window failure
	staleKnock, _ := engine.BuildKnock(ReviveFlushRateLimits)
	binary.BigEndian.PutUint64(staleKnock[6:14], uint64(time.Now().Add(-120*time.Second).Unix()))
	// Re-sign stale packet so tag is valid for stale timestamp
	recomputeTag := func(p []byte, key []byte) {
		h := NewReviveEngine(psk, nil)
		k, _ := h.BuildKnock(p[4])
		copy(p[22:36], k[22:36])
	}
	recomputeTag(staleKnock, psk)
	_, err = engine.VerifyKnock(staleKnock, dummySrc)
	if err == nil {
		t.Fatalf("expected stale knock to fail freshness check")
	}
}

func TestReviveDNSKnockRoundTrip(t *testing.T) {
	psk := []byte("dns-revive-psk-xyz987654321fedcba")
	engine := NewReviveEngine(psk, nil)

	knock, err := engine.BuildKnock(ReviveReverseCompanion)
	if err != nil {
		t.Fatalf("BuildKnock: %v", err)
	}

	dnsPkt := FormatDNSQuery(knock)
	extracted, ok := ParseDNSQueryKnock(dnsPkt)
	if !ok {
		t.Fatalf("ParseDNSQueryKnock failed to extract knock")
	}

	act, err := engine.VerifyKnock(extracted, nil)
	if err != nil {
		t.Fatalf("VerifyKnock on extracted DNS payload failed: %v", err)
	}
	if act != ReviveReverseCompanion {
		t.Fatalf("expected action 0x%02x, got 0x%02x", ReviveReverseCompanion, act)
	}
}
