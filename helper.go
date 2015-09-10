package main

import (
	_ "crypto/aes"
	"crypto/rand"
)

func generateIV(bytes int) []byte {
	iv := make([]byte, bytes)
	// Read is a helper function that calls Reader.Read using io.ReadFull
	if _, err := rand.Read(iv); err == nil {
		return iv
	}
	return nil
}

// addPadding adds 0-padding by creating a new slice which has length
// of multiple aes.Blocksize and fill it with input slice.
func addPadding(input []byte, blocksize int) []byte {
	numBytes := int(len(input)/blocksize+1) * blocksize
	newInput := make([]byte, numBytes)
	copy(newInput, input)

	return newInput
}
