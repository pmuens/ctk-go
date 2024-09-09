// Package xchacha20poly1305 implements the XChaCha20-Poly1305 authenticated
// encryption with associated data (AEAD) algorithm as specified in
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03.
package xchacha20poly1305

import (
	"github.com/pmuens/ctk-go/ctk/chacha20poly1305"
	"github.com/pmuens/ctk-go/ctk/poly1305"
	"github.com/pmuens/ctk-go/ctk/xchacha20"
)

const (
	// ErrInvalidTag is returned if the Poly1305 tag is invalid.
	ErrInvalidTag = chacha20poly1305.ErrInvalidTag
)

// XChaCha20Poly1305 is a stateful instance of the XChaCha20-Poly1305 AEAD
// algorithm.
type XChaCha20Poly1305 struct {
	// xchacha20 is an instance of the XChaCha20 stream cipher.
	xchacha20 *xchacha20.XChaCha20

	// poly1305 is an instance of the Poly1305 one-time authenticator.
	poly1305 *poly1305.Poly1305
}

// NewXChaCha20Poly1305 creates a new instance of the XChaCha20-Poly1305 AEAD
// algorithm.
func NewXChaCha20Poly1305(key [32]byte, nonce [24]byte) *XChaCha20Poly1305 {
	// The counter needs to be set to 0 as the first block of XChaCha20 will
	// be used to generate the Poly1305 key.
	counter := [4]byte{0x00, 0x00, 0x00, 0x00}

	// Create a new instance of XChaCha20 that will be used for the AEAD construction.
	xchacha20 := xchacha20.NewXChaCha20(key, nonce, counter)

	// Use XChaCha20's first block to generated the Poly1305 key and create a new
	// instance of Poly1305 with it.
	firstBlock := xchacha20.CreateBlock()
	polyKey := chacha20poly1305.Poly1305KeyGen(firstBlock)
	poly1305 := poly1305.NewPoly1305(polyKey)

	return &XChaCha20Poly1305{
		xchacha20: xchacha20,
		poly1305:  poly1305,
	}
}

// Encrypt encrypts the plaintext via XChaCha20 and creates a message
// authentication tag for the additional authenticated data (AAD) and the generated
// ciphertext using Poly1305.
func (x *XChaCha20Poly1305) Encrypt(plaintext []byte, aad []byte) ([]byte, [16]byte) {
	// Use XChaCha20 to encrypt the plaintext (note that at this point the counter
	// is 1, given that we initialized XChaCha20 with a counter of 0 to generate
	// the Poly1305 key).
	ciphertext := x.xchacha20.XORWithKeyStream(plaintext)

	// Get the padded input for Poly1305 and create a tag based on such data.
	poly1305Input := chacha20poly1305.GeneratePoly1305Input(aad, ciphertext)
	tag := x.poly1305.GenerateTag(poly1305Input)

	return ciphertext, tag
}

// Decrypt checks if the tag generated via Poly1305 is valid using the additional
// authenticated data (AAD) and the ciphertext. If valid it decrypts the ciphertext
// using XChaCha20.
// Returns an error if the tag is invalid.
func (x *XChaCha20Poly1305) Decrypt(ciphertext []byte, aad []byte, tag [16]byte) ([]byte, error) {
	// Get the padded input for Poly1305 and create a tag based on such data.
	poly1305Input := chacha20poly1305.GeneratePoly1305Input(aad, ciphertext)
	computedTag := x.poly1305.GenerateTag(poly1305Input)

	// Return an error and exit early if the tags don't match.
	if tag != computedTag {
		return []byte{}, ErrInvalidTag
	}

	// Use XChaCha20 to decrypt the ciphertext (note that at this point the counter
	// is 1, given that we initialized XChaCha20 with a counter of 0 to generate
	// the Poly1305 key).
	plaintext := x.xchacha20.XORWithKeyStream(ciphertext)

	return plaintext, nil
}
