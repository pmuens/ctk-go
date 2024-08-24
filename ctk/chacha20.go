package ctk

import (
	"encoding/binary"
	"math/bits"
)

// ChaCha20 is a stateful instance of the ChaCha stream cipher.
type ChaCha20 struct {
	// counter is the block counter.
	counter uint32

	// key is the key used for encryption / decryption.
	key [8]uint32

	// nonce is the used nonce that shouldn't be repeated when the same key is used.
	nonce [3]uint32

	// state is the internal state on which operations are performed.
	state [16]uint32
}

// NewChaCha20 creates a new instance of the ChaCha20 stream cipher.
func NewChaCha20(key [32]byte, nonce [12]byte, counter [4]byte) *ChaCha20 {
	// Key bits.
	k := [8]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	}

	// Counter.
	b := binary.LittleEndian.Uint32(counter[:])

	// Nonce bits.
	n := [3]uint32{
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	}

	// State.
	var s = initState(k, n, b)

	return &ChaCha20{
		counter: b,
		key:     k,
		nonce:   n,
		state:   s,
	}
}

// createBlock produces a 512 bit ChaCha20 block by permuting the state via 10
// double rounds (10 * 2 = 20 rounds in total).
func (s *ChaCha20) createBlock() [16]uint32 {
	s.state = initState(s.key, s.nonce, s.counter)
	old_state := s.state

	for range 10 {
		s.doubleRound()
	}

	for i, val := range old_state {
		s.state[i] += val
	}

	// Increment the counter.
	s.counter += 1

	return s.state
}

// doubleRound permutes the state by running two rounds in sequence
// (one column round and one diagonal round).
func (s *ChaCha20) doubleRound() [16]uint32 {
	s.columnRound()
	s.diagonalRound()
	return s.state
}

// columnRound applies the quarterRound function to the state columns.
func (s *ChaCha20) columnRound() [16]uint32 {
	s.quarterRound(0, 4, 8, 12)
	s.quarterRound(1, 5, 9, 13)
	s.quarterRound(2, 6, 10, 14)
	s.quarterRound(3, 7, 11, 15)
	return s.state
}

// diagonalRound applies the quarterRound function to the state diagonals.
func (s *ChaCha20) diagonalRound() [16]uint32 {
	s.quarterRound(0, 5, 10, 15)
	s.quarterRound(1, 6, 11, 12)
	s.quarterRound(2, 7, 8, 13)
	s.quarterRound(3, 4, 9, 14)
	return s.state
}

// quarterRound is an implementation of the ChaCha quarter round function	that
// permutes ChaCha's internal state.
// x, y, z, and w are used to index into the state.
func (s *ChaCha20) quarterRound(x, y, z, w int) [16]uint32 {
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

// initState initializes and returns the state that's used by ChaCha20.
func initState(key [8]uint32, nonce [3]uint32, counter uint32) [16]uint32 {
	// Constant "expand 32-byte k".
	constant := [4]uint32{
		0x61707865, // expa
		0x3320646e, // nd 3
		0x79622d32, // 2-by
		0x6b206574, // te k
	}

	var state [16]uint32

	copy(state[0:4], constant[:])
	copy(state[4:12], key[:])
	state[12] = counter
	copy(state[13:16], nonce[:])

	return state
}
