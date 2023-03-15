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
	"os"
)

func main() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("ERR GENERATE KEY : ", err.Error())
		return
	}

	// ================= encode pem
	// extract pubkey
	pubkey := &privkey.PublicKey
	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		fmt.Println("ERR PUB KEY : ", err.Error())
		return
	}

	file, err := os.Create("ENCPUB.pem")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer file.Close()
	pem.Encode(file, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeybytes,
	})

	privfile, err := os.Create("ENCPRIV.pem")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer privfile.Close()

	privkeybytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	pemPrivateBlock, _ := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", privkeybytes, []byte("secret"), x509.PEMCipherAES256)
	// pemPrivateBlock := &pem.Block{
	// 	Type:    "PRIVATE KEY",
	// 	Headers: nil,
	// 	Bytes:   privkeybytes,
	// }
	/* Encode block to file */
	if errEncode := pem.Encode(privfile, pemPrivateBlock); errEncode != nil {
		println("failed to encode pemblock to file")
		return
	}

	fmt.Println("STRING PUBKEY : ", string(pubkeybytes))

	//================================
	hash := sha256.Sum256([]byte("test message"))
	sign, err := rsa.SignPKCS1v15(nil, privkey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Println("ERR SIGNING : ", err.Error())
		return
	}
	signature := base64.StdEncoding.EncodeToString(sign)

	// =============VERIFY
	pubkeys := ImportPUBPEMTEST("PUBTEST.pem", "")
	signBytes, _ := base64.StdEncoding.DecodeString(signature)

	if err := rsa.VerifyPKCS1v15(pubkeys, crypto.SHA256, hash[:], signBytes); err != nil {
		fmt.Println("FALSE")
		return
	}

	fmt.Println("TRUE")

}

func ImportPUBPEMTEST(filename, password string) *rsa.PublicKey {
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
	pub_key, errLoad := LoadPublicKey(block, password)
	if errLoad != nil {
		println("failed to load key")
		os.Exit(1)
	}

	return pub_key
}

func LoadPublicKey(block *pem.Block, password string) (*rsa.PublicKey, error) {
	if password != "" {
		blockBytes, errDecrypt := x509.DecryptPEMBlock(block, []byte(password))
		if errDecrypt != nil {
			println("failed to decrypt block")
			panic(errDecrypt)
		}
		pub, err := x509.ParsePKIXPublicKey(blockBytes)
		return pub.(*rsa.PublicKey), err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	return pub.(*rsa.PublicKey), err
}
