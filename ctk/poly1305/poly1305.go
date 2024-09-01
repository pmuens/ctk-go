// Package poly1305 implements the Poly1305 one-time authenticator as specified
// in https://datatracker.ietf.org/doc/html/rfc8439.
package poly1305

import (
	"math"
	"math/big"
	"slices"
)

// BlockSize is the size (in bytes) of the input to be processed at a time.
const BlockSize = 16

// P is the prime 2^130-5.
var P *big.Int

// Need to use the init function as P can't be a constant.
// See: https://stackoverflow.com/a/49831018
func init() {
	P, _ = new(big.Int).SetString("3fffffffffffffffffffffffffffffffb", 16)
}

// Poly1305 is a stateful instance of the Poly1305 one-time authenticator.
type Poly1305 struct {
	// accum is the accumulator which is used to compute the tag.
	accum *big.Int

	// r are the key's first 16 bytes which were clamped and turned into a big int.
	r *big.Int

	// s are the key's last 16 bytes turned into a big int.
	s *big.Int
}

// NewPoly1305 creates a new instance of the Poly1305 MAC.
func NewPoly1305(key [32]byte) *Poly1305 {
	// Extract r from the key by taking its first 16 bytes.
	var r [16]byte
	copy(r[:], key[0:16])

	// Clamp r.
	r = clamp(r)

	// Turn r into a big endian byte slice so that it can be used in a big integer
	// conversion.
	rSlice := r[:]
	slices.Reverse(rSlice)
	rBigInt := new(big.Int).SetBytes(rSlice)

	// Extract s form the key by taking its last 16 bytes.
	var s [16]byte
	copy(s[:], key[16:32])

	// Turn s into a big endian byte slice so that it can be used in a big integer
	// conversion.
	sSlice := s[:]
	slices.Reverse(sSlice)
	sBigInt := new(big.Int).SetBytes(sSlice)

	// Set the accumulator to zero.
	accum := big.NewInt(0)

	return &Poly1305{
		r:     rBigInt,
		s:     sBigInt,
		accum: accum,
	}
}

// GenerateTag creates the tag to authenticate the data.
func (p *Poly1305) GenerateTag(data []byte) [16]byte {
	numBlocks := int(math.Ceil(float64(len(data)) / BlockSize))

	for i := range numBlocks {
		// A block is a BlockSize bytes (or less) block from the input data.
		// Default to slice from the last sliced block to the end (to handle blocks
		// that have fewer than BlockSize bytes).
		block := data[(i * BlockSize):]
		// Check if an exact BlockSize byte block can be slices and slice it, if so.
		if (i+1)*BlockSize < len(data) {
			block = data[(i * BlockSize):((i + 1) * BlockSize)]
		}

		// Create a copy of the block to ensure that we're not mutating the
		// original data directly.
		blockCopy := slices.Clone(block)

		// Add one bit to the end of the block.
		blockCopy = append(blockCopy, 0x01)

		// Reverse the block to turn it into a big endian version so that it can be
		// used in a big integer conversion.
		slices.Reverse(blockCopy)
		n := new(big.Int).SetBytes(blockCopy)

		// Add the current, modified block interpreted as a number to the accumulator.
		accum := new(big.Int).Add(p.accum, n)
		// Multiply the accumulator by r.
		accum = new(big.Int).Mul(accum, p.r)
		// Reduce the accumulator modulo P.
		accum = new(big.Int).Mod(accum, P)

		// Save the updated accumulator.
		p.accum = accum
	}

	// Add s to the accumulator and access the underlying bytes (in big endian order).
	result := new(big.Int).Add(p.accum, p.s).Bytes()

	// If there are fewer than 16 bytes we need to add zero padding for the missing
	// bytes.
	if len(result) < 16 {
		toPad := 16 - len(result)
		for range toPad {
			// Prepend 0x00 as the padding.
			// See: https://stackoverflow.com/a/53737602
			result = append([]byte{0x00}, result...)
		}
	}

	// Access the last 16 bytes.
	bytes := result[len(result)-16:]

	// Reverse slice to turn the big endian order into little endian order.
	slices.Reverse(bytes)

	// Create tag which is an array of the 16 bytes.
	var tag [16]byte
	copy(tag[:], bytes)

	return tag
}

// clamp clamps the r value according to the specification.
func clamp(r [16]byte) [16]byte {
	r[3] &= 15
	r[7] &= 15
	r[11] &= 15
	r[15] &= 15

	r[4] &= 252
	r[8] &= 252
	r[12] &= 252

	return r
}
