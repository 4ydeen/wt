//go:build !linux

package wat

func totalSystemRAMMB() int {
	// Safe fallback on non-Linux hosts (e.g. Windows dev machines)
	return 4096
}
