package encryptor_rsa

import (
	"os"
	"encoding/base64"
)

func createFile(filePath, content string) error {

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)

	return err
}

func toBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func fromBase64(in string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}
	return b, nil
}