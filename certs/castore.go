package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/spf13/viper"
	"github.com/stormentt/ssh-cert-man/util"
	"golang.org/x/crypto/ssh"
)

type CAStore struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey

	N uint64
}

func LoadCA() (CAStore, error) {
	storepath := viper.GetString("ca.path")
	jsonBytes, err := os.ReadFile(storepath)
	if err != nil {
		return CAStore{}, err
	}

	var castore CAStore
	err = json.Unmarshal(jsonBytes, &castore)
	if err != nil {
		return CAStore{}, err
	}

	return castore, nil
}

func (ca CAStore) Sign(outPath string, inPath string, certType uint32, principals []string, extensions []string, id string) error {
	keyBytes, err := os.ReadFile(inPath)
	if err != nil {
		log.Printf("unable to read in public key bytes: %s", err)
		return err
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		log.Printf("unable to parse public key bytes: %s", err)
		return err
	}

	extensionMap := make(map[string]string)
	for _, v := range extensions {
		extensionMap[v] = ""
	}

	now := time.Now()
	expire := now.Add(time.Hour * 86400)
	cert := ssh.Certificate{
		Key:             pubKey,
		Serial:          ca.N,
		KeyId:           id,
		ValidBefore:     uint64(expire.Unix()),
		ValidAfter:      uint64(now.Unix()),
		CertType:        certType,
		ValidPrincipals: principals,
		Permissions:     ssh.Permissions{Extensions: extensionMap},
	}

	signer, err := ssh.NewSignerFromKey(ca.Priv)
	if err != nil {
		log.Printf("unable to instantiate signer: %s", err)
		return err
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		log.Printf("unable to sign cert: %s", err)
		return err
	}

	outBytes := util.MarshalCert(cert)
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)

	_, err = outFile.Write(outBytes)
	if err != nil {
		log.Printf("unable to write cert: %s", err)
		return err
	}

	err = outFile.Close()
	return err
}
