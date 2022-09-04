/** Here uses triple des encryption algorithm*/
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	//DES operates on data block of 64 bits in size (1 bytes = 8 bits)
	plainText := "8bytestx"

	//in general, triple des key consists of 3 independent keys wheareas each of them has 8 bytes size
	key1 := "pass1234"
	key2 := "pass5678"
	key3 := "pass9012"

	var key string
	keys := make([]string, 0, 3)
	keys = append(keys, key1, key2, key3)
	for i := 0; i < len(keys); i++ {
		key += keys[i]
	}

	//Convert []string to []byte
	// buf := &bytes.Buffer{}
	// gob.NewEncoder(buf).Encode(keys)
	// keybyts := buf.Bytes()

	// file := EncryptTripleDES([]byte(key), plainText)
	// DecryptTripleDES(file, []byte(key))

	encryptedstr := EncryptDES_CBC_Mode([]byte(key), plainText)
	fmt.Println(encryptedstr)
	decryptedstr := DescryptDES_CBCMode([]byte(key), plainText, encryptedstr)
	fmt.Println(hex.DecodeString(decryptedstr))
}

func EncryptTripleDES(key []byte, plainText string) string {
	//Create cipher block
	cipherBlock, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println("failed to create block", err)
		os.Exit(1)
	}

	plainTextByts := []byte(plainText)
	out := make([]byte, len(plainText))
	//standard encryption, no mode
	cipherBlock.Encrypt(out, plainTextByts)

	return hex.EncodeToString(out)

}

func EncryptDES_CBC_Mode(key []byte, plaintext string) string {
	plaintextbyts := []byte(plaintext)

	padbyts := PKCS5Padding(plaintextbyts, des.BlockSize, len(plaintext))
	//Create cipher block
	cipherBlock, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println("failed to create block", err)
		os.Exit(1)
	}

	ciphertext := make([]byte, len(padbyts))
	iv := []byte("1234567890123456")

	//blockmodes (cbc)
	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	mode.CryptBlocks(ciphertext, padbyts)

	return hex.EncodeToString(ciphertext)
}

func DecryptTripleDES(file string, key []byte) {
	fileBytes, err := hex.DecodeString(file)
	if err != nil {
		println("failed to decode data")
		os.Exit(1)
	}

	//verify
	cipherBlock, errcipher := des.NewTripleDESCipher(key)
	if errcipher != nil {
		println("failed to create cipher block")
		os.Exit(1)
	}

	origin := make([]byte, len(file))
	cipherBlock.Decrypt(origin, fileBytes)

	fmt.Println(string(origin[:]))
}

func DescryptDES_CBCMode(key []byte, plaintext string, file string) string {
	encrypted, _ := hex.DecodeString(file)
	cipherBlock, err := des.NewTripleDESCipher(key)
	if err != nil {
		fmt.Println("failed to create block", err)
		os.Exit(1)
	}

	padbyts := PKCS5Padding([]byte(plaintext), des.BlockSize, len(plaintext))
	ciphertext := make([]byte, len(padbyts))
	iv := []byte("1234567890123456")

	decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
	// decrypted := make([]byte, len(plaintext))
	decrypter.CryptBlocks(ciphertext, encrypted)

	return hex.EncodeToString(ciphertext)
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
