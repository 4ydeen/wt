package wat

import (
	"bytes"
	"os"
	"strconv"
)

func totalSystemRAMMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 2048
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("MemTotal:")) {
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.Atoi(string(fields[1]))
				if err == nil && kb > 0 {
					return kb / 1024
				}
			}
		}
	}
	return 2048
}
