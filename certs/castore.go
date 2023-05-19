package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/stormentt/ssh-cert-man/util"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
)

type CAStore struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey

	N uint64
}

func (ca CAStore) Save(output string, pw []byte, salt []byte) error {
	if salt == nil {
		salt = make([]byte, 32)
		_, err := rand.Read(salt)
		if err != nil {
			return err
		}
	}

	key, err := stretchKey(pw, salt)
	if err != nil {
		return err
	}

	var keyBytes [32]byte
	copy(keyBytes[:], key)

	var nonceBytes [24]byte
	_, err = rand.Read(nonceBytes[:])
	if err != nil {
		return err
	}

	marshalled, err := ca.Marshal()
	if err != nil {
		return err
	}

	encryptedBytes := secretbox.Seal(nil, marshalled, &nonceBytes, &keyBytes)
	wrapped := wrappedStore{
		Nonce:          nonceBytes[:],
		Salt:           salt,
		EncryptedStore: encryptedBytes,
	}

	outBytes, err := json.Marshal(wrapped)
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = outFile.Write(outBytes)
	if err != nil {
		return err
	}

	return outFile.Close()
}

func LoadCA(caPath string, pw []byte) (CAStore, error) {
	wrappedBytes, err := os.ReadFile(caPath)
	if err != nil {
		log.Printf("unable to read wrapped ca file: %s", err)
		return CAStore{}, err
	}

	var wrapped wrappedStore
	err = json.Unmarshal(wrappedBytes, &wrapped)
	if err != nil {
		log.Printf("unable to unmarshal wrapped ca bytes: %s", err)
		return CAStore{}, err
	}

	key, err := stretchKey(pw, wrapped.Salt)
	if err != nil {
		log.Printf("unable to decrypt: %s", err)
		return CAStore{}, err
	}

	var nonceBytes [24]byte
	var keyBytes [32]byte

	if len(key) != 32 {
		return CAStore{}, &KeyLengthError{}
	}

	if len(wrapped.Nonce) != 24 {
		return CAStore{}, &NonceLengthError{}
	}

	copy(nonceBytes[:], wrapped.Nonce)
	copy(keyBytes[:], key)

	decrypted, ok := secretbox.Open(nil, wrapped.EncryptedStore, &nonceBytes, &keyBytes)
	if !ok {
		return CAStore{}, &DecryptionError{}
	}

	return unmarshalCA(decrypted)
}

func unmarshalCA(jsonBytes []byte) (CAStore, error) {
	var castore CAStore
	err := json.Unmarshal(jsonBytes, &castore)
	if err != nil {
		return CAStore{}, err
	}

	return castore, nil
}

func (ca CAStore) Marshal() ([]byte, error) {
	return json.Marshal(ca)
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
	if err != nil {
		log.Printf("unable to create cert file: %s", err)
		return err
	}

	_, err = outFile.Write(outBytes)
	if err != nil {
		log.Printf("unable to write cert: %s", err)
		return err
	}

	err = outFile.Close()
	return err
}
