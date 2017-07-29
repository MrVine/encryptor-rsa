package main

import (
	rsa "encryptor-rsa"
	"fmt"
)

func main() {
	encryptor, _ := rsa.GenerateEncryptor(2048)

	plainText := "This is a test string for RSA :)"
	encrypted, _ := encryptor.Encrypt(plainText)
	decrypted, _ := encryptor.Decrypt(encrypted)

	fmt.Printf("%30s: %s", "Plain text", plainText)
	fmt.Printf("%30s: %s", "Encrypted text", encrypted)
	fmt.Printf("%30s: %s", "Decrypted text", decrypted)

	// converts public key to base64-formatted string (that you can save it, share it etc.)
	publicKeyPEM, keyError := encryptor.GetPublicKeyAsPEM()
	if keyError != nil {
		fmt.Println("Can't convert public-key to PEM-formatted string")
		fmt.Println(keyError)
		return
	}

	// converts private key to base64-formatted string
	privateKeyPEM := encryptor.GetPrivateKeyAsPem()

	// this method is required to simulate creation of new encryptor on the other machine
	encryptor = rsa.GenerateVoidEncryptor()

	encryptor.SetPublicKeyFromPEM(publicKeyPEM)
	encrypted2, _ := encryptor.Encrypt(plainText)

	fmt.Printf("%30s: %s", "Plain text", plainText)
	fmt.Printf("%30s: %s", "Encrypted text", encrypted)

	encryptor.SetPrivateKeyFromPEM(privateKeyPEM)
	decrypted2, _ := encryptor.Decrypt(encrypted2)

	fmt.Printf("%30s: %s", "Decrypted text", decrypted2)
}
