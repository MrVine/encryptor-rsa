package encryptor_rsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/rsa"
)

func (e *RsaEncryptor) GetPublicKeyAsPem() (string, error) {

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

func (e *RsaEncryptor) GetPrivateKeyAsPem() (p string, err error) {

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&e.PrivateKey),
	}

	if e.Password != "" {
		block, err = x509.EncryptPEMBlock(
			randReader,
			block.Type,
			block.Bytes,
			[]byte(e.Password),
			x509.PEMCipherAES256,
		)
		if err != nil {
			return
		}
	}

	p = string(pem.EncodeToMemory(block))

	return
}

func (e *RsaEncryptor) SetPrivateKeyFromPEM(privateKeyString string) error {

	block, _ := pem.Decode([]byte(privateKeyString))
	if block == nil {
		return errors.New("failed to parse PEM block containing the key: block is nil")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to parse PEM block containing the key: block.type is " + block.Type)
	}

	x509.DecryptPEMBlock(block, []byte(e.Password))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	e.PrivateKey = *key
	return nil
}

func (e *RsaEncryptor) SavePublicKeyInPem(filePath string) error {

	content, err := e.GetPublicKeyAsPem()
	if err != nil {
		return err
	}

	return createFile(filePath, content)
}

func (e *RsaEncryptor) SavePrivateKeyInPem(filePath string) error {

	content, err := e.GetPrivateKeyAsPem()
	if err != nil {
		return err
	}

	return createFile(filePath, content)
}
