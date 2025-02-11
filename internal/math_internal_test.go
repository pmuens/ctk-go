package internal

import "testing"

func TestAdd(t *testing.T) {
	tt := map[string]struct {
		a    int
		b    int
		want int
	}{
		"1 + 2": {a: 1, b: 2, want: 3},
		"2 + 3": {a: 2, b: 3, want: 5},
		"3 + 4": {a: 3, b: 4, want: 7},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := add(tc.a, tc.b)

			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}
