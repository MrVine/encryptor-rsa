package encryptor_rsa

import "crypto/rsa"

func Init(keyLength int) (e RsaEncryptor, err error) {

	key, err := rsa.GenerateKey(randReader, keyLength)
	if err != nil {
		return e, err
	}

	e = RsaEncryptor{
		PrivateKey: *key,
		PublicKey:  key.PublicKey,
	}

	return e, nil
}

func InitWithPassword(keyLength int, password string) (e RsaEncryptor, err error) {

	e, err = Init(keyLength)
	if err == nil {
		e.Password = password
	}

	return
}

func InitEmpty() RsaEncryptor {
	return RsaEncryptor{}
}

