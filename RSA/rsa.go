package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

func GeneratePrivPubKey() (*rsa.PrivateKey, rsa.PublicKey) {
	private_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		println("failed to generate private key")
		panic(err)
	}

	// this public key is a part of rsa.PrivateKey struct
	public_key := private_key.PublicKey
	return private_key, public_key
}

func GeneratePubKeyToByte(pubkey *rsa.PublicKey) ([]byte, error) {
	public_key, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pubkeybytes := ssh.MarshalAuthorizedKey(public_key)
	return pubkeybytes, nil
}

func WriteKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}
	return nil
}

func ExportPEM() {
	private_key, _ := GeneratePrivPubKey()

	/* PEM Block
	#Encode RSA key pair (i.e x509/etc.)
		#Bytes : result of encoded key */
	file, errFile := os.Create("PRIV.pem")
	if errFile != nil {
		println("failed to create file")
		panic(errFile)
	}

	/* Inside block where the encoded key is put */
	pemPrivateBlockWithPass, _ := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(private_key), []byte("secret"), x509.PEMCipherAES128)

	// pemPrivateBlock := &pem.Block{
	// 	Type:    "RSA PRIVATE KEY",
	// 	Headers: nil,
	// 	Bytes:   x509.MarshalPKCS1PrivateKey(private_key),
	// }

	/* Encode block to file */
	if errEncode := pem.Encode(file, pemPrivateBlockWithPass); errEncode != nil {
		println("failed to encode pemblock to file")
		os.Exit(1)
	}

	/* (Optional) save generated public key to another file or pem.
	for pem can follow the previous instruction to encode and decode pem file*/
	public_key_byt, errp := GeneratePubKeyToByte(&private_key.PublicKey)
	if errp != nil {
		println("failed to generate key to byte")
		panic(errp)
	}
	WriteKeyToFile(public_key_byt, "PUBKEY.pub") // Save in another extension file

	// Save key into pem block
	pemPublicBlock := &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(&private_key.PublicKey),
	}

	pubfile, _ := os.Create("PUB.pem")
	defer pubfile.Close()
	if errEncode := pem.Encode(pubfile, pemPublicBlock); errEncode != nil {
		println("failed to encode pemblock to file")
		os.Exit(1)
	}

	defer file.Close()
}

func LoadPrivateKey(block *pem.Block, password string) (*rsa.PrivateKey, error) {
	if password != "" {
		blockBytes, errDecrypt := x509.DecryptPEMBlock(block, []byte(password))
		if errDecrypt != nil {
			println("failed to decrypt block")
			panic(errDecrypt)
		}
		return x509.ParsePKCS1PrivateKey(blockBytes)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func LoadPubKey(block *pem.Block, password string) (*rsa.PublicKey, error) {
	if password != "" {
		blockBytes, errDecrypt := x509.DecryptPEMBlock(block, []byte(password))
		if errDecrypt != nil {
			println("failed to decrypt block")
			panic(errDecrypt)
		}
		return x509.ParsePKCS1PublicKey(blockBytes)
	}

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func ImportPEM(filename, password string) (*rsa.PrivateKey, rsa.PublicKey) {
	file, err := os.Open(filename)
	defer file.Close()

	if err != nil {
		println("failed to open file")
		os.Exit(1)
	}

	fileInfo, _ := file.Stat()
	pemByts := make([]byte, fileInfo.Size())

	buffer := bufio.NewReader(file)
	if _, errReading := buffer.Read(pemByts); errReading != nil {
		println("failed to read file")
		panic(errReading)
	}

	/* Decode the content of file(block(key)) */
	block, _ := pem.Decode(pemByts)
	private_key, errLoad := LoadPrivateKey(block, password)
	if errLoad != nil {
		println("failed to load key")
		os.Exit(1)
	}

	return private_key, private_key.PublicKey
}

func ImportPUBPEM(filename, password string) *rsa.PublicKey {
	file, err := os.Open(filename)
	defer file.Close()

	if err != nil {
		println("failed to open file")
		os.Exit(1)
	}

	fileInfo, _ := file.Stat()
	pemByts := make([]byte, fileInfo.Size())

	buffer := bufio.NewReader(file)
	if _, errReading := buffer.Read(pemByts); errReading != nil {
		println("failed to read file")
		panic(errReading)
	}

	/* Decode the content of file(block(key)) */
	block, _ := pem.Decode(pemByts)
	pub_key, errLoad := LoadPubKey(block, password)
	if errLoad != nil {
		println("failed to load key")
		os.Exit(1)
	}

	return pub_key
}

func Encrypt(data string) []byte {
	_, public_key := ImportPEM("FILE.pem", "secret")

	/* Encrypt the given data/message
	#hash : algorithm used to hash the message (i.e sha256/sha512/etc.)
	#rand : generate random bits for hashed message (so the output of hashed str doesnt result in the same ciphertext) */
	encryptedByts, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &public_key, []byte(data), nil)
	if err != nil {
		println("failed to encrypt data")
		panic(err)
	}
	return encryptedByts
}

func Decrypt(encryptedFiles []byte, pass string) string {
	private_key, _ := ImportPEM("FILE.pem", "secret")
	decryptedFile, err := private_key.Decrypt(nil, encryptedFiles, &rsa.OAEPOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		println("failed to decrypt file")
		os.Exit(1)
	}

	strBytes := string(decryptedFile)
	return strBytes
}

/** SIGN AND VERIFY */
/* Receiver will use signature to verify the message is valid */
var message = "this is message owned by user1 for user2"

func Signing() string {
	private_key, _ := ImportPEM("PRIV.pem", "secret")

	/* Message will be hashed -> cipher text */
	msgHasher := sha256.New()
	msgHasher.Write([]byte(message))
	msgBytes := msgHasher.Sum(nil)

	/* Create signature of the data (i.e SignPSS/SignPKCS1v15) using our private_key,
	the hashing algorithm we used for signature, then hashed message */
	signBytes, errSigning := rsa.SignPKCS1v15(nil, private_key, crypto.SHA256, msgBytes)
	if errSigning != nil {
		println("failed to create signature")
		os.Exit(1)
	}

	signature := base64.StdEncoding.EncodeToString(signBytes)
	return signature
}

func Verify() bool {
	//_, public_key := ImportPEM("PRIV.pem", "") // OR
	public_key := ImportPUBPEM("PUB.pem", "")

	signature := Signing()
	signBytes, _ := base64.StdEncoding.DecodeString(signature)

	msgHasher := sha256.New()
	msgHasher.Write([]byte(message))
	msgBytes := msgHasher.Sum(nil)

	/* This verifies the incoming signature */
	if err := rsa.VerifyPKCS1v15(public_key, crypto.SHA256, msgBytes, signBytes); err != nil {
		return false
	}
	return true
}

func main() {
	ExportPEM()

	data := "clientid|timestamp"
	dataByts := Encrypt(data)
	originalFile := Decrypt(dataByts, "secret")
	println(originalFile)

	fmt.Printf("isVerified: %v", Verify())
}
