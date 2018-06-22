package encryptor_rsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/rsa"
)

func (e *RsaEncryptor) GetPublicKeyAsPEM() (string, error) {

	bytes, err := x509.MarshalPKIXPublicKey(&e.PublicKey)
	if err != nil {
		return "", err
	}

	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: bytes,
		},
	)
	return string(p), nil
}

func (e *RsaEncryptor) SetPublicKeyFromPEM(publicKeyString string) error {

	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		return errors.New("failed to parse PEM block: block is nil")
	}

	if block.Type != "RSA PUBLIC KEY" {
		return errors.New("failed to parse PEM block: block has incorrect type")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	switch keyType := key.(type) {
	case *rsa.PublicKey:
		e.PublicKey = *keyType
		return nil
	default:
		return errors.New("key type is not RSA")
	}

}

