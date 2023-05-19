package certs

import (
	"golang.org/x/crypto/scrypt"
)

type SaltLengthError struct{}

func (e *SaltLengthError) Error() string {
	return "salt length must be 32 bytes"
}

type KeyLengthError struct{}

func (e *KeyLengthError) Error() string {
	return "key length must be 32 bytes"
}

type NonceLengthError struct{}

func (e *NonceLengthError) Error() string {
	return "nonce length must be 24 bytes"
}

type DecryptionError struct{}

func (e *DecryptionError) Error() string {
	return "decryption failed: possibly wrong password or corrupt data"
}

// StretchKey(input, salt) (output, salt, err)
// output is a 32 byte (256 bit) key
func stretchKey(input []byte, salt []byte) ([]byte, error) {
	if len(salt) != 32 {
		return nil, &SaltLengthError{}
	}

	return scrypt.Key(input, salt, 32768, 8, 1, 32)
}

type wrappedStore struct {
	Salt           []byte
	Nonce          []byte
	EncryptedStore []byte
}
