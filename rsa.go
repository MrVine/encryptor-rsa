package encryptor_rsa

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

var (
	randReader = rand.Reader
)

const (
	PrivateKeyFileExtension = ".pem"
	DefaultKeyLength        = 2048
)

type RsaEncryptor struct {
	PrivateKey rsa.PrivateKey
	PublicKey  rsa.PublicKey
	Password   string
}

func GetEncryptedDataLength() int {
	return 344
}

func (e *RsaEncryptor) Execute(command string, message string) (string, error) {

	switch command {
	case "encrypt":
		return e.Encrypt(message)
	case "decrypt":
		return e.Decrypt(message)
	default:
		return "", errors.New("unsupported command: " + command)
	}
}

func (e *RsaEncryptor) EncryptBytes(plain []byte) ([]byte, error) {

	cipher, err := rsa.EncryptOAEP(
		sha256.New(),
		randReader,
		&e.PublicKey,
		plain,
		[]byte(""),
	)

	if err != nil {
		return nil, err
	}

	return []byte(toBase64(cipher)), nil
}

func (e *RsaEncryptor) Encrypt(plain string) (string, error) {

	encrypted, err := e.EncryptBytes([]byte(plain))
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

func (e *RsaEncryptor) DecryptBytes(encrypted []byte) ([]byte, error) {

	decoded, err := fromBase64(string(encrypted))
	if err != nil {
		return nil, err
	}

	decrypted, err := rsa.DecryptOAEP(
		sha256.New(),
		randReader,
		&e.PrivateKey,
		[]byte(decoded),
		[]byte(""),
	)

	return decrypted, nil
}

func (e *RsaEncryptor) Decrypt(encryptedData string) (string, error) {

	decrypted, err := e.DecryptBytes([]byte(encryptedData))
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}
