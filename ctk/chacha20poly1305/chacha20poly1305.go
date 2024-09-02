// Package chacha20poly1305 implements the ChaCha20-Poly1305 authenticated
// encryption with associated data (AEAD) algorithm as specified in
// https://datatracker.ietf.org/doc/html/rfc8439.
package chacha20poly1305

import "github.com/pmuens/ctk-go/ctk/chacha20"

// poly1305KeyGen generates the Poly1305 key via the ChaCha20 block function.
func poly1305KeyGen(key [32]byte, nonce [12]byte) [32]byte {
	// The counter needs to be set to 0.
	counter := [4]byte{0x00, 0x00, 0x00, 0x00}

	// Create a new ChaCha20 instance with the passed-in key, nonce and the counter
	// set to 0.
	cha := chacha20.NewChaCha20(key, nonce, counter)
	// Create the first block of 512 bit state.
	block := cha.CreateBlock()

	// The Poly1305 key will be 256 bit long (128 bit for the r and 128 bit for
	// the s value).
	var result [32]byte

	// Only the first 256 bit of the 512 bit ChaCha20 state will be used.
	// Iterate over every word (32 bit) of those 256 bit.
	for i, word := range block[0:8] {
		index := (i * 4)

		// Extract the individual bytes from the word.
		result[index] = byte(word)
		result[index+1] = byte(word >> 8)
		result[index+2] = byte(word >> 16)
		result[index+3] = byte(word >> 24)
	}

	return result
}
