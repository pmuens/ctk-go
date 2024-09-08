// Package xchacha20 implements the XChaCha20 stream cipher as specified in
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03.
package xchacha20

import "github.com/pmuens/ctk-go/ctk/chacha20"

// XChaCha20 is a stateful instance of XChaCha20.
type XChaCha20 struct {
	// chacha20 is an instance of the ChaCha20 stream cipher.
	chacha20 *chacha20.ChaCha20
}

// NewXChaCha20 creates a new instance of XChaCha20.
func NewXChaCha20(key [32]byte, nonce [24]byte, counter [4]byte) *XChaCha20 {
	// The nonce for HChaCha20 consists of the first 16 bytes of the 24 byte nonce.
	hChaChaNonce := [16]byte(nonce[0:16])
	hCha := NewHChaCha20(key, hChaChaNonce)

	// Generate a subKey via HChaCha20 which will be the key used for ChaCha20.
	subKey := hCha.GenerateSubKey()

	// The nonce for ChaCha20 consists of the last 8 bytes of the 24 byte nonce
	// prefixed with 4 zero bytes (as RFC 8439 specifies a 12 byte ChaCha20 nonce).
	chaChaNonce := [12]byte(append([]byte{0x00, 0x00, 0x00, 0x00}, nonce[16:24]...))
	chacha20 := chacha20.NewChaCha20(subKey, chaChaNonce, counter)

	return &XChaCha20{
		chacha20: chacha20,
	}
}

// XORWithKeyStream creates a key stream using the ChaCha20 block function
// and XOR's the data with such key stream to create the return value.
// This function is used for both, encryption and decryption.
func (x *XChaCha20) XORWithKeyStream(data []byte) []byte {
	// Reuse the ChaCha20 XORWithKeyStream function.
	return x.chacha20.XORWithKeyStream(data)
}
