package main

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	_ "fmt"
)

func encryptDES(input, key, iv []byte, tripleDES bool) ([]byte, error) {
	var block cipher.Block
	var err error
	if tripleDES {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = des.NewCipher(key)
	}

	if err != nil {
		return nil, errors.New("Couldn't create block cipher.")
	}
	if len(input)%des.BlockSize != 0 {
		input = addPadding(input, des.BlockSize)
	}
	output := make([]byte, len(input))

	for i := 0; i < len(input)/des.BlockSize; i++ {
		start := des.BlockSize * i
		end := start + des.BlockSize
		block.Encrypt(output[start:end], input[start:end])
	}
	return output, nil
}

func decryptDES(input, output, key []byte, tripleDES bool) error {
	var block cipher.Block
	var err error
	if tripleDES {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = des.NewCipher(key)
	}

	if err != nil {
		return errors.New("Couldn't create block cipher.")
	}

	for i := 0; i < len(input)/des.BlockSize; i++ {
		start := des.BlockSize * i
		end := start + des.BlockSize
		block.Decrypt(output[start:end], input[start:end])
	}
	return nil
}
