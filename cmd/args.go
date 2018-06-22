package main

import (
	"flag"
	"os"
	"strconv"
	rsa "github.com/mrvine/encryptor-rsa"
	"crypto/rand"
	"fmt"
	"strings"
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

	cmd := flag.String("cmd", "", `Usage:
		encrypt <message>
		decrypt <message>
	`)

	flag.Parse()

	keyLength, err := strconv.Atoi(*keyLengthStr)
	if err != nil || !rsa.IsValidKeyLength(keyLength) {
		keyLength = rsa.DefaultKeyLength
	}

	args.KeyLength = keyLength

	if *publicKeyFile == "" {
		*publicKeyFile = "public_" + getRandomString(16) + ".txt"
	}

	if *privateKeyFile == "" {
		*privateKeyFile = "private_" + getRandomString(16) + ".txt"
	}

	args.PublicKeyPath = *publicKeyFile
	args.PrivateKeyPath = *privateKeyFile

	args.PrivateKeyPassword = *privateKeyPassword

	arr := strings.SplitN(*cmd, " ", 2)
	args.Command = arr[0]
	args.Message = arr[1]

	return
}

func getRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return fmt.Sprintf("%X", bytes)
}
