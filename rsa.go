package encryptor_rsa

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"github.com/pkg/errors"
)

var (
	randReader = rand.Reader
	keyLength  = []int{1024, 2048, 4096}
)

const (
	DefaultKeyLength = 2048
)

type RsaEncryptor struct {
	PrivateKey rsa.PrivateKey
	PublicKey  rsa.PublicKey
	Password   string
}

// Init initializes RsaEncryptor with default key length,
// empty password and just generated public/private keys.
func Init() (e RsaEncryptor, err error) {
	return InitWithKeyLength(DefaultKeyLength)
}

// InitWithKeyLength initializes RsaEncryptor with specified
// key length, empty password and just generated public/private keys.
func InitWithKeyLength(keyLength int) (e RsaEncryptor, err error) {
	return InitWithPassword(keyLength, "")
}

// InitWithPassword initializes RsaEncryptor with specified
// key length, specified password and just generated public/private keys.
func InitWithPassword(keyLength int, password string) (e RsaEncryptor, err error) {

	key, err := rsa.GenerateKey(randReader, keyLength)
	if err != nil {
		return e, err
	}

	e = RsaEncryptor{
		PrivateKey: *key,
		PublicKey:  key.PublicKey,
		Password:   password,
	}

	return e, nil
}

func InitEmpty() RsaEncryptor {
	return RsaEncryptor{}
}

func InitEmptyWithPassword(password string) RsaEncryptor {
	return RsaEncryptor{Password: password}
}

func (e *RsaEncryptor) Encrypt(plain string) (string, error) {

	encrypted, err := e.EncryptBytes([]byte(plain))
	if err != nil {
		return "", errors.Wrap(err, "can not encrypt bytes")
	}

	return string(encrypted), nil
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

func (e *RsaEncryptor) Decrypt(encryptedData string) (string, error) {

	decrypted, err := e.DecryptBytes([]byte(encryptedData))
	if err != nil {
		return "", errors.Wrap(err, "can not decrypt bytes")
	}

	return string(decrypted), nil
}

func (e *RsaEncryptor) DecryptBytes(encrypted []byte) ([]byte, error) {

	decoded, err := fromBase64(string(encrypted))
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(
		sha256.New(),
		randReader,
		&e.PrivateKey,
		[]byte(decoded),
		[]byte(""),
	)
}

func GetKeyLengths() []int {
	return keyLength
}

func GetKeyLengthString() string {
	str := fmt.Sprint(keyLength)
	replaced := strings.Replace(str, " ", ", ", -1)
	return strings.Trim(replaced, "[]")
}

func IsValidKeyLength(keyLength int) bool {
	for _, length := range GetKeyLengths() {
		if keyLength == length {
			return true
		}
	}
	return false
}
