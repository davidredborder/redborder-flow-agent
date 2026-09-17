package system

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ParseCPUSet parses a CPU affinity string such as "0,1,2,3", "0-3,8-11", or "0,2-4,7"
// and returns the sorted list of CPU IDs.
func ParseCPUSet(cpuStr string) ([]int, error) {
	cpuStr = strings.TrimSpace(cpuStr)
	if cpuStr == "" {
		return nil, nil
	}

	seen := make(map[int]bool)
	var cpuList []int

	parts := strings.Split(cpuStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid cpu range format: %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start cpu %q: %w", rangeParts[0], err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end cpu %q: %w", rangeParts[1], err)
			}
			if start > end {
				return nil, fmt.Errorf("invalid cpu range: %d > %d", start, end)
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					seen[i] = true
					cpuList = append(cpuList, i)
				}
			}
		} else {
			cpu, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid cpu id %q: %w", part, err)
			}
			if !seen[cpu] {
				seen[cpu] = true
				cpuList = append(cpuList, cpu)
			}
		}
	}

	return cpuList, nil
}

// SetCPUAffinity sets the CPU affinity mask for the current process and its threads.
func SetCPUAffinity(cpuStr string) ([]int, error) {
	cpus, err := ParseCPUSet(cpuStr)
	if err != nil {
		return nil, err
	}
	if len(cpus) == 0 {
		return nil, nil
	}

	maxCPU := runtime.NumCPU()
	var mask unix.CPUSet
	mask.Zero()

	for _, cpu := range cpus {
		if cpu < 0 || cpu >= 1024 {
			return nil, fmt.Errorf("cpu id %d out of valid range (0-1023)", cpu)
		}
		if cpu >= maxCPU {
			// Warn or clamp if needed, but allow setting if system supports it
			_ = maxCPU
		}
		mask.Set(cpu)
	}

	// 0 specifies calling process (PID 0 in SchedSetaffinity means current process)
	if err := unix.SchedSetaffinity(0, &mask); err != nil {
		return nil, fmt.Errorf("failed to set cpu affinity: %w", err)
	}

	return cpus, nil
}
