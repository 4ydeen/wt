package wat

import (
	"runtime"
	"sync"
)

type HardwareTier string

const (
	TierLean     HardwareTier = "lean"     // <= 1.5 GB RAM or 1 CPU: memory bounded to prevent OOM
	TierStandard HardwareTier = "standard" // 1.5 - 4 GB RAM, 2 CPUs: balanced high-speed
	TierHighPerf HardwareTier = "highperf" // >= 4 GB RAM, >= 2 CPUs: maximum throughput, uncapped pipe
)

type HardwareProfile struct {
	NumCPU           int
	TotalRAMMB       int
	Tier             HardwareTier
	DefaultPoolConns int
	DefaultSessions  int
	WinCap           uint64
	MaxSessionWin    uint64
	PoolLowat        int
}

var (
	hostProfileOnce sync.Once
	hostProfile     HardwareProfile
)

// HostProfile returns the hardware profile auto-detected for the current host.
func HostProfile() HardwareProfile {
	hostProfileOnce.Do(func() {
		cpus := runtime.NumCPU()
		ram := totalSystemRAMMB()

		tier := TierStandard
		if ram <= 1536 || cpus <= 1 {
			tier = TierLean
		} else if ram >= 3500 && cpus >= 2 {
			tier = TierHighPerf
		}

		conns := 8
		sessions := 1
		winCap := uint64(16 << 20)
		maxSessWin := uint64(64 << 20)
		lowat := 128 << 10

		switch tier {
		case TierLean:
			conns = 8
			sessions = 1
			winCap = 4 << 20 // pin to base window, prevent N x 16MB buffer explosion
			maxSessWin = 32 << 20
			lowat = 64 << 10
		case TierStandard:
			conns = 16
			if cpus >= 2 {
				sessions = 2
			}
			winCap = 16 << 20
			maxSessWin = 64 << 20
			lowat = 128 << 10
		case TierHighPerf:
			conns = 24
			if cpus >= 4 {
				conns = 32
				sessions = 4
			} else {
				sessions = 2
			}
			winCap = 32 << 20
			maxSessWin = 128 << 20
			lowat = 256 << 10
		}

		hostProfile = HardwareProfile{
			NumCPU:           cpus,
			TotalRAMMB:       ram,
			Tier:             tier,
			DefaultPoolConns: conns,
			DefaultSessions:  sessions,
			WinCap:           winCap,
			MaxSessionWin:    maxSessWin,
			PoolLowat:        lowat,
		}
	})
	return hostProfile
}
