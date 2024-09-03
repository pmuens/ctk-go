// Package chacha20poly1305 implements the ChaCha20-Poly1305 authenticated
// encryption with associated data (AEAD) algorithm as specified in
// https://datatracker.ietf.org/doc/html/rfc8439.
package chacha20poly1305

import (
	"encoding/binary"
	"slices"

	"github.com/pmuens/ctk-go/ctk/chacha20"
	"github.com/pmuens/ctk-go/ctk/poly1305"
)

const (
	// ErrInvalidTag is returned if the Poly1305 tag is invalid.
	ErrInvalidTag = Error("invalid Poly1305 tag")
)

// ChaCha20Poly1305 is a stateful instance of the ChaCha20-Poly1305 AEAD
// algorithm.
type ChaCha20Poly1305 struct {
	// key is the key used for encryption / decryption.
	key [32]byte

	// nonce is the used nonce that shouldn't be repeated when the same key is used.
	nonce [12]byte

	// chacha20 is an instance of the ChaCha20 stream cipher.
	chacha20 *chacha20.ChaCha20

	// poly1305 is an instance of the Poly1305 one-time authenticator.
	poly1305 *poly1305.Poly1305
}

// NewChaCha20Poly1305 creates a new instance of the ChaCha20-Poly1305 AEAD
// algorithm.
func NewChaCha20Poly1305(key [32]byte, nonce [12]byte) *ChaCha20Poly1305 {
	// The counter needs to be set to 0 as the first block of ChaCha20 will
	// be used to generate the Poly1305 key.
	counter := [4]byte{0x00, 0x00, 0x00, 0x00}

	// Create a new instance of ChaCha20 that will be used for the AEAD construction.
	chacha20 := chacha20.NewChaCha20(key, nonce, counter)

	// Use ChaCha20 to generated the Poly1305 key and create a new instance of
	// Poly1305 with it.
	polyKey := poly1305KeyGen(chacha20)
	poly1305 := poly1305.NewPoly1305(polyKey)

	return &ChaCha20Poly1305{
		key:      key,
		nonce:    nonce,
		chacha20: chacha20,
		poly1305: poly1305,
	}
}

// Encrypt encrypts the plaintext via ChaCha20 and creates a message
// authentication tag for the additional authenticated data (AAD) and the generated
// ciphertext using Poly1305.
func (c *ChaCha20Poly1305) Encrypt(plaintext []byte, aad []byte) ([]byte, [16]byte) {
	// Use ChaCha20 to encrypt the plaintext (note that at this point the counter
	// is 1, given that we initialized ChaCha20 with a counter of 0 to generate
	// the Poly1305 key).
	ciphertext := c.chacha20.XORWithKeyStream(plaintext)

	// Get the padded input for Poly1305 and create a tag based on such data.
	poly1305Input := generatePoly1305Input(aad, ciphertext)
	tag := c.poly1305.GenerateTag(poly1305Input)

	return ciphertext, tag
}

// Decrypt checks if the tag generated via Poly1305 is valid using the additional
// authenticated data (AAD) and the ciphertext. If valid it decrypts the ciphertext
// using ChaCha20.
// Returns an error if the tag is invalid.
func (c *ChaCha20Poly1305) Decrypt(ciphertext []byte, aad []byte, tag [16]byte) ([]byte, error) {
	// Get the padded input for Poly1305 and create a tag based on such data.
	poly1305Input := generatePoly1305Input(aad, ciphertext)
	computedTag := c.poly1305.GenerateTag(poly1305Input)

	// Return an error and exit early if the tags don't match.
	if tag != computedTag {
		return []byte{}, ErrInvalidTag
	}

	// Use ChaCha20 to decrypt the ciphertext (note that at this point the counter
	// is 1, given that we initialized ChaCha20 with a counter of 0 to generate
	// the Poly1305 key).
	plaintext := c.chacha20.XORWithKeyStream(ciphertext)

	return plaintext, nil
}

// generatePoly1305Input creates the (padded) input to be processed by Poly1305
// to create a tag.
func generatePoly1305Input(aad []byte, ciphertext []byte) []byte {
	// Add padding to AAD so that its total length is a multiple of 16.
	paddedAad := padTo16Bytes(aad)

	// Add padding to ciphertext so that its total length is a multiple of 16.
	paddedCiphertext := padTo16Bytes(ciphertext)

	// Calculate length of AAD and turn it into bytes in little endian order.
	// See: https://stackoverflow.com/a/29062148
	aadLength := make([]byte, 8)
	binary.LittleEndian.PutUint32(aadLength, uint32(len(aad)))

	// Calculate length of ciphertext and turn it into bytes in little endian order.
	// See: https://stackoverflow.com/a/29062148
	cipertextLength := make([]byte, 8)
	binary.LittleEndian.PutUint32(cipertextLength, uint32(len(ciphertext)))

	// Create an empty result byte slice that has a capacity of the data that
	// Poly1305 will compute a tag for.
	result := make([]byte, 0, len(paddedAad)+len(paddedCiphertext)+len(aadLength)+len(cipertextLength))

	// 1. Additional authenticated data (AAD).
	// 2. Padding #1 (>= 15 zero bytes. Total length = multiple of 16).
	result = append(result, paddedAad...)

	// 3. Ciphertext
	// 4. Padding #2 (>= 15 zero bytes. Total length = multiple of 16).
	result = append(result, paddedCiphertext...)

	// 5. Length of AAD in octets as 64 bit little endian integer.
	result = append(result, aadLength...)

	// 6. Length of ciphertext in octets as 64 bit little endian integer.
	result = append(result, cipertextLength...)

	return result
}

// padTo16Bytes appends up to 15 zero bytes so that the data byte slice is always
// a multiple of 16 bytes.
// Note that the data that's passed-in won't be mutated, but a modified copy will
// be returned.
func padTo16Bytes(data []byte) []byte {
	// Don't do anything if length of data is already divisible by 16.
	if len(data)%16 == 0 {
		return data
	}

	result := slices.Clone(data)

	toPad := 16 - (len(data) % 16)
	for range toPad {
		// Append 0x00 as the padding.
		result = append(result, 0x00)
	}

	return result
}

// poly1305KeyGen generates the Poly1305 key via the ChaCha20 block function.
func poly1305KeyGen(chacha20 *chacha20.ChaCha20) [32]byte {
	// Create the first block of 512 bit state.
	block := chacha20.CreateBlock()

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
