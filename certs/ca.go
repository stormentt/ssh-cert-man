package certs

import (
	"crypto/ed25519"
	"encoding/json"
	"os"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func GenerateCA() (ssh.Signer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	err = saveKeys(pub, priv)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(priv)
}

func saveKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	castore := CAStore{
		pub,
		priv,
		0,
	}

	jsonBytes, err := json.Marshal(castore)
	if err != nil {
		return err
	}

	outPath := viper.GetString("ca.path")
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	_, err = outFile.Write(jsonBytes)
	if err != nil {
		return err
	}

	err = outFile.Close()
	return err
}
