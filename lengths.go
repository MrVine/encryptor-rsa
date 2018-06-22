package encryptor_rsa

import (
	"fmt"
	"strings"
)

var (
	keyLength = []int{1024, 2048, 4096}
)

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