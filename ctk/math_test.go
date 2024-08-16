package ctk_test

import (
	"errors"
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

func TestDiv(t *testing.T) {
	tt := map[string]struct {
		a        int
		b        int
		expected int
		err      error
	}{
		"2 / 1":  {a: 2, b: 1, expected: 2, err: nil},
		"1 / 0":  {a: 1, b: 0, expected: 0, err: ctk.ErrDivisionByZero},
		"2 / 2":  {a: 2, b: 2, expected: 1, err: nil},
		"12 / 2": {a: 12, b: 2, expected: 6, err: nil},
		"3 / 2":  {a: 3, b: 2, expected: 1, err: nil},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := ctk.Div(tc.a, tc.b)

			if !errors.Is(err, tc.err) {
				t.Errorf("expected error %v, got %v", tc.err, err)
			}

			if got != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}
