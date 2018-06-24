package encryptor_rsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/rsa"
	pkg_errors"github.com/pkg/errors"
	"fmt"
)

// GetPublicKeyAsPem allows to get public key in PEM-encoded string
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

// SetPublicKeyFromPem allows to set public key to current instance
// of RsaEncryptor from PEM-encoded string.
func (e *RsaEncryptor) SetPublicKeyFromPem(publicKeyString string) error {

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

// GetPrivateKeyAsPem allows to get private key in PEM-encoded string.
// If e.Password is not empty - private key will be encrypted
// via AES 256 CBC encryption algorithm, where key is e.Password.
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

// SetPrivateKeyFromPem allows to set private key to current instance
// of RsaEncryptor from PEM-encoded string. If private key was encrypted -
// this method will try to decrypt via password from e.Password field.
func (e *RsaEncryptor) SetPrivateKeyFromPem(privateKeyString string) (err error) {

	decoded, _ := pem.Decode([]byte(privateKeyString))
	if decoded == nil {
		return errors.New("failed to parse PEM block containing the key: block is nil")
	}

	if decoded.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to parse PEM block containing the key: block.type is " + decoded.Type)
	}

	var bytes []byte

	if x509.IsEncryptedPEMBlock(decoded) {
		bytes, err = x509.DecryptPEMBlock(decoded, []byte(e.Password))
		if err != nil {
			return pkg_errors.Wrap(err, "can not decrypt private key")
		}
		fmt.Println("private key is decrypted")
	} else {
		bytes = []byte(decoded.Bytes)
		fmt.Println("private key was not decrypted")
	}

	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return err
	}

	e.PrivateKey = *key
	return nil
}

// SavePublicKeyInPem allows to save current public key to file.
func (e *RsaEncryptor) SavePublicKeyInPem(filePath string) error {

	content, err := e.GetPublicKeyAsPem()
	if err != nil {
		return err
	}

	return createFile(filePath, content)
}

// SavePrivateKeyInPem allows to save current private key to file.
func (e *RsaEncryptor) SavePrivateKeyInPem(filePath string) error {

	content, err := e.GetPrivateKeyAsPem()
	if err != nil {
		return err
	}

	return createFile(filePath, content)
}
