package wat

import (
	"testing"
)

func TestHardwareProfile(t *testing.T) {
	hp := HostProfile()
	t.Logf("Detected: CPUs=%d, TotalRAM=%d MB, Tier=%s, PoolConns=%d, WinCap=%d MB, MaxSessionWin=%d MB",
		hp.NumCPU, hp.TotalRAMMB, hp.Tier, hp.DefaultPoolConns, hp.WinCap>>20, hp.MaxSessionWin>>20)
	if hp.NumCPU < 1 {
		t.Fatalf("invalid NumCPU: %d", hp.NumCPU)
	}
	if hp.TotalRAMMB < 1 {
		t.Fatalf("invalid TotalRAMMB: %d", hp.TotalRAMMB)
	}
	if hp.WinCap < streamWindow {
		t.Fatalf("WinCap too low: %d", hp.WinCap)
	}
}
