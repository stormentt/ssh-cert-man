package util

import (
	"bytes"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

func MarshalCert(cert ssh.Certificate) []byte {
	b := &bytes.Buffer{}
	b.WriteString(cert.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(cert.Marshal())
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}
