# encryptor-rsa
![](https://travis-ci.com/MrVine/encryptor-rsa.svg?branch=master)

![](https://user-images.githubusercontent.com/5161479/41833585-8ba0ab08-7859-11e8-91bf-499d7fe06ac2.png)

`encryptor-rsa` is a golang library. Using this library you can:
* to encrypt/decrypt data via RSA OAEP encryption algorithm
* to serialize/deserialize RSA OAEP keys in PEM format (with password protection).

This repository contains:
* `encryptor-rsa` library itself
* `demonstration` - it is console application, which demonstrates main ideas of this library.
* `cmd` - it is console application, which allows to:
  * generate public/private keys (private key can be protected by password)
  * encrypt message with existing public key
  * decrypt message with existing private key

Also [wiki](https://github.com/MrVine/encryptor-rsa/wiki) page is available.

# Usage example

## Initialize encryptor

Initialization depends on how do you want to use `RsaEncryptor`. In case of you want to generate new public/private keys **without** password protection, you can use: 
```
func Init() (e RsaEncryptor, err error)
func InitWithKeyLength(keyLength int) (e RsaEncryptor, err error) {
```

If you want to do the same, but protect your private key **with** a password (using AES 256 CBC encryption) during serialization, you can use:
```
func InitWithPassword(keyLength int, password string) (RsaEncryptor, error)
```

In case you want to encrypt message with existing public key, or decrypt message with existing **unencrypted private key**, you can use:
```
func InitEmpty() (RsaEncryptor, error)
```

If you want to do the same, but use **encrypted private key**, you should use:
```
func InitEmptyWithPassword(password string) (RsaEncryptor, error)
```

## Encrypt

To encrypt you can use following methods:

1. `func (e *RsaEncryptor) Encrypt(message string) (string, error)`
2. `func (e *RsaEncryptor) EncryptBytes(plain []byte) ([]byte, error)`

## Decrypt

To decrypt you can use following methods:

1. `func (e *RsaEncryptor) Decrypt(plain string) (string, error)`
2. `func (e *RsaEncryptor) DecryptBytes(plain []byte) ([]byte, error)`

**NOTICE**: you can't decrypt message, if private key was encrypted but password for this private key was not specified

## PEM Serialization

To get public key in PEM-encoded string, you can use following method:
```
func (e *RsaEncryptor) GetPublicKeyAsPem() (string, error)
```

To get private key in PEM-encoded string, you can use this method:
```
func (e *RsaEncryptor) GetPrivateKeyAsPem() (p string, err error)
```

**NOTICE**: PEM-encoded string with private key will be protected by password ONLY if `e.Password` was already set for `e` instance

To set public key from PEM-encoded string to `e` instance, you can use following method:
```
func (e *RsaEncryptor) SetPublicKeyFromPem(publicKeyString string) error
```

To set private key from PEM-encoded string to `e`, you can use this method:
```
func (e *RsaEncryptor) SetPrivateKeyFromPem(privateKeyString string) (err error)
```

**NOTICE**: password-protected PEM-encoded string will be decrypted ONLY if `e.Password` was already set for `e` instance
