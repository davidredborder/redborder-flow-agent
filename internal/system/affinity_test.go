package system

import (
	"reflect"
	"testing"
)

func TestParseCPUSet(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		hasErr   bool
	}{
		{
			input:    "",
			expected: nil,
			hasErr:   false,
		},
		{
			input:    "0",
			expected: []int{0},
			hasErr:   false,
		},
		{
			input:    "0,1,2,3",
			expected: []int{0, 1, 2, 3},
			hasErr:   false,
		},
		{
			input:    "0-3",
			expected: []int{0, 1, 2, 3},
			hasErr:   false,
		},
		{
			input:    "0-2,4,6-7",
			expected: []int{0, 1, 2, 4, 6, 7},
			hasErr:   false,
		},
		{
			input:    "0,0,1,1-2",
			expected: []int{0, 1, 2},
			hasErr:   false,
		},
		{
			input:    "3-1",
			expected: nil,
			hasErr:   true,
		},
		{
			input:    "invalid",
			expected: nil,
			hasErr:   true,
		},
	}

	for _, tt := range tests {
		res, err := ParseCPUSet(tt.input)
		if tt.hasErr {
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for input %q: %v", tt.input, err)
			}
			if !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("for input %q expected %v, got %v", tt.input, tt.expected, res)
			}
		}
	}
}

func TestSetCPUAffinity(t *testing.T) {
	// Pin to CPU 0 (available on all Linux runners)
	cpus, err := SetCPUAffinity("0")
	if err != nil {
		t.Logf("SetCPUAffinity returned %v (could be permission/container restriction)", err)
		return
	}
	if len(cpus) != 1 || cpus[0] != 0 {
		t.Errorf("expected [0], got %v", cpus)
	}
}
