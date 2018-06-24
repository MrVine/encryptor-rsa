package main

import
(
	"flag"
	"os"
	"crypto/rand"
	"fmt"
	"errors"
	"strconv"
	rsa "github.com/mrvine/encryptor-rsa"
)

type RsaArgs struct {
	KeyLength          int
	PublicKeyPath      string
	PrivateKeyPath     string
	PrivateKeyPassword string
	Command            string
	Message            string
}

func getArgs() (args RsaArgs, err error) {

	command := flag.String(
		"command",
		"",
		`command to do (generate/encrypt/decrypt)`,
	)

	message := flag.String(
		"message",
		"",
		`message to encrypt/decrypt`,
	)

	keyLengthStr := flag.String(
		"keyLength",
		os.Getenv("KEY_LENGTH"),
		"RSA encryptor key length",
	)

	publicKeyFile := flag.String(
		"public",
		os.Getenv("PUBLIC_KEY_FILE"),
		"public-key file path",
	)

	privateKeyFile := flag.String(
		"private",
		os.Getenv("PRIVATE_KEY_FILE"),
		"private-key file path",
	)

	privateKeyPassword := flag.String(
		"password",
		os.Getenv("PRIVATE_FILE_PASSWORD"),
		"password to file with private key",
	)

	flag.Parse()

	/*
	/* Can be uncommented for debug purposes
	/*
	fmt.Println("command:", *command)
	fmt.Println("message:", *message)
	fmt.Println("key-length: ", *keyLengthStr)
	fmt.Println("public-key-file:", *publicKeyFile)
	fmt.Println("private-key-file:", *privateKeyFile)
	fmt.Println("private-key-password:", *privateKeyPassword)
	*/

	if *command == "" || (*command != "generate" && *message == "") {
		err = errors.New("[command] and [message] arguments are required")
		return
	}

	if *command == "encrypt" && *publicKeyFile == "" {
		err = errors.New("you should specify public key to encrypt")
		return
	}

	if *command == "decrypt" && *privateKeyFile == "" {
		err = errors.New("you should specify private key to decrypt")
		return
	}

	if *command == "generate" {
		if *keyLengthStr == "" {
			*keyLengthStr = "0"
		}

		keyLength32, err := strconv.ParseInt(*keyLengthStr, 10, 32)
		keyLength := int(keyLength32)
		if err != nil || !rsa.IsValidKeyLength(keyLength) {
			yellowConsole.Println(
				"incorrect key length. default key length",
				rsa.DefaultKeyLength,
				"bits will be used",
			)
			keyLength = rsa.DefaultKeyLength
		}

		args.KeyLength = keyLength
	}


	args.PublicKeyPath = *publicKeyFile
	args.PrivateKeyPath = *privateKeyFile

	args.PrivateKeyPassword = *privateKeyPassword

	args.Command = *command
	args.Message = *message

	return
}

func getRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return fmt.Sprintf("%X", bytes)
}
