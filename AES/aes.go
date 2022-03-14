package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {

	plainText := "Hello world"
	plainTextByts := []byte(plainText)

	//Here generates 32 bytes as authentication key. (32/64 bytes)
	keypass := "32bytespassphraseor32digitspass1"
	keyEncoded := []byte(keypass)

	//For random 32 bytes
	// keypass := make([]byte, 32)
	// _, err := rand.Read(keypass)
	// if err != nil {
	// 	println("failed to generate random key")
	// 	os.Exit(1)
	// }

	//Plain text -> AES cipher text
	//#create cipher block.
	cipherBlock, errcipher := aes.NewCipher([]byte(keyEncoded))
	if errcipher != nil {
		println("failed to create cipher block")
		os.Exit(1)
	}

	//Perform GCM encryption
	//Cipher block is wrapped in GCM (
	// 	#an operation mode of block cipher that uses universal hashing over a binary
	//	#Galois field to provide authenticated encrypted.
	//	#It will be implemented in hardware to achieve high speed.)
	gcm, errgcm := cipher.NewGCM(cipherBlock)
	if errgcm != nil {
		println("failed to perform GCM encryption")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, errnonce := io.ReadFull(rand.Reader, nonce); errnonce != nil {
		println(errnonce)
	}

	//This file contains the message and the key
	encrypted := gcm.Seal(nonce, nonce, plainTextByts, nil)
	if errwritting := ioutil.WriteFile("EncryptedText.txt", encrypted, 0777); errwritting != nil {
		println("failed to write file")
		os.Exit(1)
	}

	DecryptAES("EncryptedText.txt")
}

/** Here will verify the received data by receiver sent by sender is verified.
#by using the same shared key
*/
func DecryptAES(file string) {
	urkey := "32bytespassphraseor32digitspass1"
	urkeybyts := []byte(urkey)

	//Receiver receive the message
	cipherText, errReading := ioutil.ReadFile(file)
	if errReading != nil {
		println("failed to read file")
		os.Exit(1)
	}

	//Verify by using your key
	cipherBlock, err := aes.NewCipher(urkeybyts)
	if err != nil {
		println("failed to create cipher block")
		os.Exit(1)
	}

	gcm, errgcm := cipher.NewGCM(cipherBlock)
	if errgcm != nil {
		println("failed to perform GCM encryption")
	}

	//Result should be same as the origin file
	noncesize := gcm.NonceSize()
	if len(cipherText) < noncesize {
		panic(errgcm)
	}

	//Get the key and the message
	nonce, ciphertext := cipherText[:noncesize], cipherText[noncesize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plaintext))
}
