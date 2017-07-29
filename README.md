# encryptor-rsa
Golang simple implementation of RSA OAEP encryption algorithm with serializing possibilities (PEM format)



# Description
Frequently all what we need from encryption packages is:

func Encrypt(plain string) string

func Decrypt(encrypted string) string

func GetKey() string

func SetKey(key string) 

methods. That is all. And this library gives it to you. Now, you do not need to search good "Golang RSA OAEP library" in the web -- here it is :)



# Main features

 • very simple to use
 
 • PEM-format serialization is supported
 
 • Tested under Windows XP/7/8/8.1/10



Usage example you can find inside /main.go file
