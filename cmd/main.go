package main

import (
	rsa "github.com/mrvine/encryptor-rsa"
	"flag"
	"github.com/fatih/color"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
)

var (
	redConsole    = color.New(color.FgRed)
	yellowConsole = color.New(color.FgYellow)
	greenConsole  = color.New(color.FgGreen)
)

func generate(args RsaArgs) (string, error) {

	e, err := rsa.Init(args.KeyLength)
	if err != nil {
		return "", errors.Wrap(err, "can not initialize rsa encryptor")
	}

	if args.PublicKeyPath == "" {
		args.PublicKeyPath = "public_" + getRandomString(16) + ".txt"
	}

	if args.PrivateKeyPath == "" {
		args.PrivateKeyPath = "private_" + getRandomString(16) + ".txt"
	}

	err = e.SavePublicKeyInPem(args.PublicKeyPath)
	if err != nil {
		return "", errors.Wrap(err, "can not create public key file")
	}

	err = e.SavePrivateKeyInPem(args.PrivateKeyPath)
	if err != nil {
		return "", errors.Wrap(err, "can not create private key file")
	}

	return fmt.Sprintf(
			"public key is saved to [%s] file,\n" +
			"and private key is saved to [%s] file",
			args.PublicKeyPath,
			args.PrivateKeyPath,),
		nil
}

func encrypt(args RsaArgs) (string, error){

	e := rsa.InitEmpty()

	bytes, err := ioutil.ReadFile(args.PublicKeyPath)
	if err != nil {
		return "", errors.Wrap(err,
			"can not read a content of the file with public key",
		)
	}

	err = e.SetPublicKeyFromPEM(string(bytes))
	if err != nil {
		return "", errors.Wrap(err, "can not set public key")
	}

	return e.Encrypt(args.Message)
}

func decrypt(args RsaArgs) (string, error) {

	e := rsa.InitEmpty()

	bytes, err := ioutil.ReadFile(args.PrivateKeyPath)
	if err != nil {
		return "", errors.Wrap(err,
			"can not read a content of the file with private key",
		)
	}

	err = e.SetPrivateKeyFromPEM(string(bytes))
	if err != nil {
		return "", errors.Wrap(err, "can not set private key")
	}

	return e.Decrypt(args.Message)
}

func getHandler(command string) func(args RsaArgs) (string, error) {

	switch command {
	case "generate":
		return generate
	case "encrypt":
		return encrypt
	case "decrypt":
		return decrypt
	default:
		return func(args RsaArgs) (string, error) {
			return "", errors.New(
				fmt.Sprintf("unknown command: %s\n", args.Command),
			)
		}
	}
}

func main() {

	args, err := getArgs()
	if err != nil {
		redConsole.Println("args parsing error:", err)
		flag.PrintDefaults()
		return
	}

	hander := getHandler(args.Command)

	result, err := hander(args)
	if err != nil {
		redConsole.Printf(
			"[%s] command execution is failed. reason: %s\n",
			args.Command,
			err,
		)
		return
	}

	greenConsole.Printf("[%s] command execution is done\n", args.Command)

	if result != "" {
		greenConsole.Printf(
			"result: %s\n",
			result,
		)
	}
}
