/* This file is sample of rsa encryption with pbe (key encrypted by PBE)*/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

/* Encryption type : RSA
Generated key (private key) will be encrypted using PBE with cipher AES-256 */

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	private_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return private_key, nil
}

func LoadPrivateKey(block *pem.Block, password string) (*rsa.PrivateKey, error) {
	if password != "" {
		privkeybytes, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
		privatekey, err := x509.ParsePKCS8PrivateKey(privkeybytes)
		return privatekey.(*rsa.PrivateKey), err
	}
	privatekey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return privatekey.(*rsa.PrivateKey), err

}

/* PRF
IV (Initialization Vector) It is a fixed-size random or pseudo-random value that is used as an additional input to the encryption algorithm along with the encryption key.
The purpose of the IV is to ensure that even if the same plaintext is encrypted multiple times using the same key,
the resulting ciphertext will be different.

KDF (Derived Key)
Algorithm func to create one or more secret keys from a secret value*/
func GenerateDerivedKey(password, salt []byte) []byte {
	keylen := 32
	iter := 1000 // number of times the key will be encrypted
	crypto_key := pbkdf2.Key(password, salt, iter, keylen, sha1.New)
	return crypto_key
}

func ExportPEM() {
	file, err := os.Create("PRIV.PEM")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	private_key, err := GenerateRSAKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	// Convert rsa key to bytes by marshalling
	privkeybytes, _ := x509.MarshalPKCS8PrivateKey(private_key)
	// Put byte key to block
	privatePemBlock := &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privkeybytes,
	}
	// Encode pem block
	if err := pem.Encode(file, privatePemBlock); err != nil {
		fmt.Println(err)
		return
	}
}

func ImportPEM(pemfile, password string) (*rsa.PrivateKey, error) {
	pembytes, err := ioutil.ReadFile(pemfile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pembytes)
	if block == nil {
		return nil, errors.New("no pem data is found")
	}
	return LoadPrivateKey(block, password)
}

func EncryptPrivKeyWithAES256() ([]byte, error) {
	msg := []byte("this is super secret message")
	// private_key, err := ImportPEM("PRIV.pem", "")
	// if err != nil {
	// 	return nil, err
	// }

	// 1. Generate salt, as an additional input of rand data used to protect "key/pass"
	// by adding a string of n-bytes or more then hashing them
	// 2. This pass will be used to encrypt(protect) a private key, at least 8 chars
	password := []byte("keysecret")
	salt := make([]byte, 16) // at least 16 bytes
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// 3. This n-bytes (in this case is 32 bytes) key will be used as a key of cipher block that protect an encrypted privkey.
	key := GenerateDerivedKey(password, salt)

	// https://xperti.io/blogs/java-aes-encryption-and-decryption/
	//AES-256 (Advanced Encryption Standard with a 256-bit key) requires a "128-bit" IV for most modes of operation,
	// including CBC (Cipher Block Chaining), CFB (Cipher Feedback), OFB (Output Feedback), and CTR (Counter).
	// However, GCM (Galois/Counter Mode) and CCM (Counter with CBC-MAC) modes of operation for AES-256 use a "96-bit" IV.

	// 4. IV is used to prevent a sequence of text that is identical to a previous sequence from producing
	// the same exact ciphertext when encrypted.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Encrypt Private Key using AES-256 (a symmetric block cipher) (32 bytes of key)
	// Create Cipher block using generated key (KDF) (SHA-X)
	// A block cipher algorithm takes a block of plaintext and a secret key as input,
	// and produces a block of ciphertext as output.
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// *Or CTR
	// In Cipher Block Chaining (CBC) mode,
	// an initialization vector (IV) is added to the first block of plaintext before encryption
	// and the resultant ciphertext is added to the next block of plaintext before encryption, and so on.
	// privkeybytes, _ := x509.MarshalPKCS8PrivateKey(private_key)

	// If the input data size is not a multiple of the block size, {16, 32, 64, ..}
	// padding needs to be added to fill the remaining space

	// i.e. len(data) = 15 -> data size is not 2x of block size means it should be {min 16/32/64/...}
	// len(data) needs 1 byte number to fulfill the block size 16
	// if len(data) > blockSize (16/32/..) then the padding will be added some rand numbers to the ceiling of block size
	dataPads := pad(msg, cipherBlock.BlockSize())
	if dataPads == nil {
		return nil, errors.New("no cipher padding generated")
	}

	// cryptographic algorithms usually operate on
	// fixed-size input blocks and the input data needs to be padded to the block size before encryption or decryption.
	cipherText := make([]byte, len(dataPads))

	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	mode.CryptBlocks(cipherText, dataPads)

	// Combine the salt and iv with the generated cipher text (encrypted key)
	cipherText_ := append(salt, iv...)
	cipherText_ = append(cipherText_, cipherText...)
	fmt.Printf("ciphertext: %x\n", cipherText)

	return cipherText_, nil
}

func DecryptPrivKeyWithAES256(data []byte) ([]byte, error) {
	// 1. Split encrypted key into its component parts
	// The salt and IV are critical components of the encryption process and are used to ensure the security of the encrypted data.
	// The salt is used as input to the key derivation function (in this case, PBKDF2) to create a derived key that is unique to the password and salt combination.
	// The IV is used to randomize the encryption process and prevent attackers from using patterns in the data to crack the encryption.
	salt := data[:16]
	iv := data[16:32]
	encprivkey := data[32:]
	password := "keysecret"

	// Step 2: Derive the key using PBKDF2 with SHA-1 (*depends)
	key := pbkdf2.Key([]byte(password), salt, 1000, 32, sha1.New)

	// Step 3: Decrypt the encrypted key using AES-256 in CBC mode
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbcDecrypter := cipher.NewCBCDecrypter(blockCipher, iv)
	decryptedKey := make([]byte, len(encprivkey))
	cbcDecrypter.CryptBlocks(decryptedKey, encprivkey)

	// Step 4: Remove any padding from the decrypted key
	return removepad(decryptedKey), nil
}

func main() {
	ExportPEM()

	cipherText, err := EncryptPrivKeyWithAES256()
	if err != nil {
		fmt.Println("Err : ", err)
		return
	}

	privkeybytes, err := DecryptPrivKeyWithAES256(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("len priv key : ", string(privkeybytes))
}

// Pad the input to a multiple of the block size
// PKCS#7 padding, which pads the input with bytes containing the number of padding bytes.
func pad(input []byte, blockSize int) []byte {
	padding := blockSize - len(input)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(input, padText...)
}

func removepad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
