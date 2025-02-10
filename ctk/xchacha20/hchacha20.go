package xchacha20

import "github.com/pmuens/xchacha20-poly1305/ctk/chacha20"

// HChaCha20 is a stateful instance of HChaCha20.
type HChaCha20 struct {
	// chacha20 is an instance of the ChaCha20 stream cipher.
	chacha20 *chacha20.ChaCha20
}

// NewHChaCha20 creates a new instance of HChaCha20.
func NewHChaCha20(key [32]byte, nonce [16]byte) *HChaCha20 {
	// Given that ChaCha20 uses a counter, but HChaCha20 doesn't and instead stores
	// a part of the nonce where the counter would be stored, we need to slice
	// the nonce to derive the counter value that's expected by ChaCha20.
	counter := [4]byte(nonce[0:4])
	slicedNonce := [12]byte(nonce[4:16])

	chacha20 := chacha20.NewChaCha20(key, slicedNonce, counter)

	return &HChaCha20{
		chacha20: chacha20,
	}
}

// GenerateSubKey generates a key usable by ChaCha20.
func (h *HChaCha20) GenerateSubKey() [32]byte {
	// Mix the state by running 20 rounds using regular ChaCha20.
	state := h.chacha20.TwentyRounds()

	// Take the first and last row of the mixed state.
	firstRow := state[0:4]
	lastRow := state[12:16]

	// The key is the bytes (little endian order) of the first- and last row.
	var key [32]byte

	// Turn words in first row into bytes with little endian order.
	for i, word := range firstRow {
		index := (i * 4)

		// Extract the individual bytes from the word.
		key[index] = byte(word)
		key[index+1] = byte(word >> 8)
		key[index+2] = byte(word >> 16)
		key[index+3] = byte(word >> 24)
	}

	// Turn words in last row into bytes with little endian order.
	for i, word := range lastRow {
		index := ((i * 4) + 16)

		// Extract the individual bytes from the word.
		key[index] = byte(word)
		key[index+1] = byte(word >> 8)
		key[index+2] = byte(word >> 16)
		key[index+3] = byte(word >> 24)
	}

	return key
}
