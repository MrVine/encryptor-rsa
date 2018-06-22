package encryptor_rsa

import (
	"os"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func (e *RsaEncryptor) SavePrivateKeyInFile(filePath string) error {

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	content, err := e.GetPrivateKeyAsPem()
	if err != nil {
		return err
	}

	file.WriteString(content)

	return nil
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

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	e.PrivateKey = *key
	return nil
}
