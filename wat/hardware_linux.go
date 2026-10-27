package wat

import (
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

func totalSystemRAMMB() int {
	return linuxRAMMB(os.ReadFile)
}

func linuxRAMMB(readFile func(string) ([]byte, error)) int {
	var ram uint64
	if data, err := readFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil && kb > 0 {
					ram = max(1, kb/1024)
				}
				break
			}
		}
	}

	cgroup, cgErr := readFile("/proc/self/cgroup")
	mountinfo, mountErr := readFile("/proc/self/mountinfo")
	if cgErr == nil && mountErr == nil {
		if limit := cgroupRAMMB(cgroup, mountinfo, readFile); limit > 0 && (ram == 0 || limit < ram) {
			ram = limit
		}
	}
	return int(min(ram, uint64(^uint(0)>>1)))
}

func cgroupRAMMB(cgroup, mountinfo []byte, readFile func(string) ([]byte, error)) uint64 {
	var ram uint64
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, mount := range strings.Split(string(mountinfo), "\n") {
		before, after, ok := strings.Cut(mount, " - ")
		fields, fs := strings.Fields(before), strings.Fields(after)
		if !ok || len(fields) < 6 || len(fs) < 3 {
			continue
		}
		var limitFile string
		switch fs[0] {
		case "cgroup2":
			limitFile = "memory.max"
		case "cgroup":
			if !slices.Contains(strings.Split(fs[2], ","), "memory") {
				continue
			}
			limitFile = "memory.limit_in_bytes"
		default:
			continue
		}
		root, mountpoint := unescape.Replace(fields[3]), unescape.Replace(fields[4])
		if !path.IsAbs(root) || path.Clean(root) != root || !path.IsAbs(mountpoint) || path.Clean(mountpoint) != mountpoint {
			continue
		}
		for _, line := range strings.Split(string(cgroup), "\n") {
			member := strings.SplitN(line, ":", 3)
			if len(member) != 3 {
				continue
			}
			if fs[0] == "cgroup2" {
				if member[0] != "0" || member[1] != "" {
					continue
				}
			} else if !slices.Contains(strings.Split(member[1], ","), "memory") {
				continue
			}
			cgroupPath := member[2]
			if !path.IsAbs(cgroupPath) || path.Clean(cgroupPath) != cgroupPath {
				continue
			}
			if cgroupPath != root && !strings.HasPrefix(cgroupPath, strings.TrimSuffix(root, "/")+"/") {
				continue
			}
			for dir := path.Join(mountpoint, strings.TrimPrefix(cgroupPath, root)); ; dir = path.Dir(dir) {
				if data, err := readFile(path.Join(dir, limitFile)); err == nil {
					if bytes, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
						// Keep known sub-MiB limits distinct from unknown capacity (zero).
						mb := max(1, bytes>>20)
						if ram == 0 || mb < ram {
							ram = mb
						}
					}
				}
				if dir == mountpoint {
					break
				}
			}
		}
	}
	return ram
}
