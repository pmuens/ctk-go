package ctk_test

import (
	"testing"

	"github.com/pmuens/ctk-go/ctk"
)

func TestMul(t *testing.T) {
	tt := map[string]struct {
		a        int
		b        int
		expected int
	}{
		"1 * 2": {a: 1, b: 2, expected: 2},
		"2 * 3": {a: 2, b: 3, expected: 6},
		"3 * 4": {a: 3, b: 4, expected: 12},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := ctk.Mul(tc.a, tc.b)

			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
