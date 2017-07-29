package encryptor_rsa

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
)

var (
	randReader = rand.Reader
	PRIVATE_KEY_FILE_EXTENSION = ".pem"
)

type RsaEncryptor struct {
	PrivateKey rsa.PrivateKey
	PublicKey rsa.PublicKey
}

func GenerateEncryptor(keyLength int) (RsaEncryptor, error) {
	var rsaEncryptor RsaEncryptor

	key, err := rsa.GenerateKey(randReader, keyLength)
	if err != nil {
		return rsaEncryptor, err
	}

	rsaEncryptor = RsaEncryptor{
		PrivateKey: *key,
		PublicKey: key.PublicKey,
	}

	return rsaEncryptor, nil
}

func GenerateVoidEncryptor() RsaEncryptor {
	return RsaEncryptor{}
}

func GetEncryptedDataLength() int {
	return 344
}

func (e *RsaEncryptor) EncryptBytes(source []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), randReader, &e.PublicKey, source, []byte(""))
	if err != nil {
		return nil, err
	}
	return []byte(toBase64(cipherText)), nil
}

func (e *RsaEncryptor) Encrypt(plainData string) (string, error) {
	encrypted, err := e.EncryptBytes([]byte(plainData))
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func (e *RsaEncryptor) DecryptBytes(source []byte) ([]byte, error) {
	b64, err := fromBase64(string(source))
	if err != nil {
		return nil, err
	}
	sourceDecoded := []byte(b64)
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), randReader, &e.PrivateKey, sourceDecoded, []byte(""))
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func (e *RsaEncryptor) Decrypt(encryptedData string) (string, error) {
	decrypted, err := e.DecryptBytes( []byte(encryptedData) )
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
