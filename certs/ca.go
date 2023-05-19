package certs

import (
	"crypto/ed25519"
)

func GenerateCA(caPath string, pw []byte) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	caStore := CAStore{
		pub,
		priv,
		0,
	}

	return caStore.Save(caPath, pw, nil)
}
