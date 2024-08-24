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

	t.Run("RFC 8439 - Test Vectors - 2.2.1", func(t *testing.T) {
		t.Parallel()

		cha := ChaCha{
			state: [16]uint32{
				0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
				0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
				0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
				0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
			},
		}

		got := cha.quarterRound(2, 7, 8, 13)
		want := [16]uint32{
			0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
			0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
			0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
			0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
		}

		if got != want {
			t.Errorf("want %v, got %v", want, got)
		}
	})
}
