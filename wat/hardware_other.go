//go:build !linux && !windows

package wat

func totalSystemRAMMB() int {
	return 0
}
