package main

import (
	"crypto/aes"
	_ "crypto/des"
	_ "encoding/base64"
	_ "encoding/hex"
	_ "errors"
	"fmt"
	//"log"
)

// TODO: support n byte pad (see TLS), not only 0 byte pad
// TODO: (DES): Support different key length and key derivations, e.g. EDE2 etc.
// TODO: support 3DES
// TODO: write tests

// Assign uints to different ciphers and modes of operation
var (
	AES uint = 1
	DES uint = 2

	CBC uint = 11
	CTR uint = 12
	CFB uint = 13
	OFB uint = 14
	// ...
)

func main() {
	//key := []byte("1234567890123456") // aes, 16 bytes
	key := []byte("12345678") // des, 8 bytes
	plaintext := []byte("Freda is the name of a cow.")
	//iv := generateIV(aes.BlockSize)
	iv := []byte("1234567890123456")
	fmt.Printf("\nKey: %v\nPlaintext: %v\nIV: %0x\n\n", string(key), string(plaintext), string(iv))

	//ciphertext, err := Encrypt(plaintext, key, nil, AES, CFB) // working: CFB, CBC, CTR, OFB
	ciphertext, err := Encrypt(plaintext, key, nil, DES, 0)
	if err != nil {
		fmt.Errorf("Couldn't encrypt: %v", err.Error())
	}
	fmt.Printf("Ciphertext: %v\n\n", ciphertext)

	plaintext, err = Decrypt(ciphertext, key, DES, 0)
	if err != nil {
		fmt.Errorf("Couldn't decrypt: %v", err.Error())
	}
	fmt.Printf("Decryption result: %v\n\n", string(plaintext))
}

// Encrypt serves as wrapper function for encrypting any plaintext,key with specified
// cipher and mode of operation
func Encrypt(plaintext, key, iv []byte, cipher, mode uint) ([]byte, error) {
	input := []byte(plaintext)
	var output []byte
	var err error

	switch cipher {
	case AES:
		output = make([]byte, aes.BlockSize+len(input))
		err = encryptAES(input, output, key, iv, mode)
	case DES:
		// No need to pass output slice because its length
		// depends on input slice length and its padding.
		// Thus output is created after appending the padding.
		output, err = encryptDES(input, key, iv)
	}

	if err != nil {
		return nil, err
	}
	return output, nil
}

// Decrypt serves as wrapper function for decrypting any ciphertext,key with specified
// cipher and mode of operation
func Decrypt(ciphertext, key []byte, cipher, mode uint) ([]byte, error) {
	input := []byte(ciphertext)
	var output []byte
	var err error

	switch cipher {
	case AES:
		output = make([]byte, len(input)-aes.BlockSize)
		err = decryptAES(input, output, key, mode)
	case DES:
		// Here we can create output before decryption
		// because its length is the same as input's length
		output = make([]byte, len(input))
		err = decryptDES(input, output, key)
	}

	if err != nil {
		return nil, err
	}
	return output, nil
}
