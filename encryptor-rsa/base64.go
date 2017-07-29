package encryptor_rsa

import "encoding/base64"

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

