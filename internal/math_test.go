package internal_test

import (
	"errors"
	"testing"

	"github.com/pmuens/xchacha20-poly1305/internal"
)

func TestMul(t *testing.T) {
	tt := map[string]struct {
		a    int
		b    int
		want int
	}{
		"1 * 2": {a: 1, b: 2, want: 2},
		"2 * 3": {a: 2, b: 3, want: 6},
		"3 * 4": {a: 3, b: 4, want: 12},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := internal.Mul(tc.a, tc.b)

			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestDiv(t *testing.T) {
	tt := map[string]struct {
		a    int
		b    int
		want int
		err  error
	}{
		"2 / 1":  {a: 2, b: 1, want: 2, err: nil},
		"1 / 0":  {a: 1, b: 0, want: 0, err: internal.ErrDivisionByZero},
		"2 / 2":  {a: 2, b: 2, want: 1, err: nil},
		"12 / 2": {a: 12, b: 2, want: 6, err: nil},
		"3 / 2":  {a: 3, b: 2, want: 1, err: nil},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := internal.Div(tc.a, tc.b)

			if !errors.Is(err, tc.err) {
				t.Errorf("want error %v, got %v", tc.err, err)
			}

			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}
