package encryptor_rsa

import (
	"os"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func (e *RsaEncryptor) SavePrivateKeyInFile(filePath string) error {
	file, err := os.Create( filePath )
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString( e.GetPrivateKeyAsPem() )

	return nil
}

func (e *RsaEncryptor) GetPrivateKeyAsPem() string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&e.PrivateKey)
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return string(privateKeyPem)
}

func (e *RsaEncryptor) SetPrivateKeyFromPEM(privateKeyString string) error {
	block, _ := pem.Decode([]byte(privateKeyString))
	if block == nil {
		return errors.New("failed to parse PEM block containing the key: block is nil")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to parse PEM block containing the key: block.type is " + block.Type)
	}

	_privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	e.PrivateKey = *_privateKey
	return nil
}

