package main

import (
	"bufio"
	"bytes"
	o "encryption/OTP"
	"fmt"
	"image/png"
	"io/ioutil"
	"os"
)

func main() {
	// OTP issuer and account will be defined if url needed.
	var otp = o.OTP{
		Period:    2 * 30,
		KeySize:   20,
		Digits:    o.DigitSix,
		Algorithm: o.AlgorithmSHA1,
	}

	// This should be encrypted to pem block [read encryption type]
	secretkey := o.GenerateKeySecret(otp)
	// Read [generated] secret key from file system
	// >>> secret := [SECRET_KEY.pem]

	//---------------------------------------------

	// Generate OTP
	yourotp := o.GenerateOTP(otp, secretkey)
	fmt.Println("Your Generated OTP : ", yourotp)

	// Generate QR with encoded url
	qrurl, err := o.GenerateURLQR(otp, secretkey)
	if err != nil {
		panic(err)
	}
	qr, errqr := qrurl.Image(200, 200)
	if errqr != nil {
		panic(errqr)
	}

	var urlbytes bytes.Buffer
	if errencode := png.Encode(&urlbytes, qr); errencode != nil {
		panic(errencode)
	}
	ioutil.WriteFile("qr.png", urlbytes.Bytes(), 0644) // >>> 0644 is octal representation of the filemode

	// Validate OTP
	// == buffered reader
	var reader = bufio.NewReader(os.Stdin)
	fmt.Print("Enter OTP : ")
	input, errread := reader.ReadString('\n')
	if errread != nil {
		panic(errread)
	}

	resp := o.ValidateOTP(input, secretkey)
	fmt.Println(resp)
}
