package ctk

import (
	"slices"
	"testing"
)

func TestChaCha20QuarterRound(t *testing.T) {
	t.Run("RFC 8439 - Test Vectors - 2.1.1", func(t *testing.T) {
		t.Parallel()

		a, b, c, d := quarterRound(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)

		got := []uint32{a, b, c, d}
		want := []uint32{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb}

		if !slices.Equal(got, want) {
			t.Errorf("want %v, got %v", want, got)
		}
	})
}
