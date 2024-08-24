package ctk

import (
	"math/bits"
)

// ChaCha is a stateful instance of the ChaCha stream cipher.
type ChaCha struct {
	// state is the internal state on which operations are performed.
	state [16]uint32
}

// quarterRound is an implementation of the ChaCha quarter round function	that
// permutes ChaCha's internal state.
// x, y, z, and w are used to index into the state.
func (s *ChaCha) quarterRound(x, y, z, w int) [16]uint32 {
	a, b, c, d := quarterRound(s.state[x], s.state[y], s.state[z], s.state[w])

	s.state[x] = a
	s.state[y] = b
	s.state[z] = c
	s.state[w] = d

	return s.state
}

// quarterRound is an implementation of the ChaCha quarter round function.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)

	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)

	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)

	return a, b, c, d
}
