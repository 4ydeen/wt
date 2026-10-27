package wat

import (
	"errors"
	"testing"
)

func TestLinuxRAMMB(t *testing.T) {
	const v2Mount = "30 25 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup rw"
	const v1Mount = "31 25 0:27 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory"
	unlimited := "9223372036854771712\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"meminfo only", map[string]string{"/proc/meminfo": "MemTotal:       2048000 kB\n"}, 2000},
		{"unknown host RAM trusts the container limit", map[string]string{
			"/proc/self/cgroup":                    "0::/docker/abc\n",
			"/proc/self/mountinfo":                 v2Mount + "\n",
			"/sys/fs/cgroup/docker/abc/memory.max": "1073741824\n",
		}, 1024},
		{"v2 max means unlimited", map[string]string{
			"/proc/meminfo":             "MemTotal:       8388608 kB\n",
			"/proc/self/cgroup":         "0::/\n",
			"/proc/self/mountinfo":      v2Mount + "\n",
			"/sys/fs/cgroup/memory.max": "max\n",
		}, 8192},
		{"v1 leaf limit", map[string]string{
			"/proc/self/cgroup":    "4:memory:/docker/abc\n",
			"/proc/self/mountinfo": v1Mount + "\n",
			"/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes": "536870912\n",
		}, 512},
		{"v1 nested leaf missing uses the parent limit", map[string]string{
			"/proc/self/cgroup":    "4:memory:/docker/abc\n",
			"/proc/self/mountinfo": v1Mount + "\n",
			"/sys/fs/cgroup/memory/docker/memory.limit_in_bytes": "268435456\n",
		}, 256},
		{"v1 unlimited is ignored", map[string]string{
			"/proc/meminfo":                               "MemTotal:       4194304 kB\n",
			"/proc/self/cgroup":                           "4:memory:/\n",
			"/proc/self/mountinfo":                        v1Mount + "\n",
			"/sys/fs/cgroup/memory/memory.limit_in_bytes": unlimited,
		}, 4096},
		{"nothing readable stays unknown", map[string]string{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(name string) ([]byte, error) {
				if s, ok := tc.files[name]; ok {
					return []byte(s), nil
				}
				return nil, errors.New("no such file")
			}
			if got := linuxRAMMB(read); got != tc.want {
				t.Fatalf("linuxRAMMB() = %d, want %d", got, tc.want)
			}
		})
	}
}
