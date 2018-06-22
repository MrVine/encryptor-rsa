package encryptor_rsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/rsa"
)

func (e *RsaEncryptor) GetPublicKeyAsPEM() (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&e.PublicKey)
	//publicKeyBytes, err := asn1.Marshal(e.PublicKey)
	if err != nil {
		return "", err
	}
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(publicKeyPem), nil
}

func (e *RsaEncryptor) SetPublicKeyFromPEM(publicKeyString string) error {
	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		return errors.New("Failed to parse PEM block containing the key: block is nil")
	}
	if block.Type != "RSA PUBLIC KEY" {
		return errors.New("Failed to parse PEM block containing the key: block.Type is " + block.Type)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	switch publicKeyConcreteType := publicKey.(type) {
	case *rsa.PublicKey:
		e.PublicKey = *publicKeyConcreteType
		return nil
	default:
		return errors.New("Key type is not RSA")
	}

}

