package tempotp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"image"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

const DigitSix Digits = 6

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

type (
	Digits int

	Algorithm int

	OTP struct {
		// Issuing Organisation e.g your provider
		Issuer string
		// Name of the user e.g username, email
		Account string
		// TOTP Valid for, in seconds
		Period uint
		// Size of generated secret key
		KeySize uint
		// Generated secret key
		KeySecret []byte
		// OTP Digit Request
		Digits Digits
		// Algorithm for HMAC
		Algorithm Algorithm
	}

	OTPValidation struct {
		// OTP input by user
		Passcode string
		// From FileSystem.
		KeySecret string
	}

	KeyURL struct {
		url *url.URL
	}
)

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmMD5:
		return md5.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	default:
		return sha1.New()
	}
}

func (a Algorithm) String() string {
	switch a {
	case AlgorithmMD5:
		return "MD5"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

// For QR
func NewTotpURL(origin string) (*KeyURL, error) {
	// remove any whitespace
	raw := strings.TrimSpace(origin)

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	return &KeyURL{
		url: u,
	}, nil
}

// Convert OTP to QR Code
func (key *KeyURL) Image(w int, h int) (image.Image, error) {
	qrcode, errqr := qr.Encode(key.GetURL(), qr.M, qr.Auto)
	if errqr != nil {
		return nil, errqr
	}

	// resize qr code with the given width and height
	qrcode, errscale := barcode.Scale(qrcode, w, h)
	if errscale != nil {
		return nil, errscale
	}

	return qrcode, nil
}

func (k *KeyURL) GetURL() string { return k.url.String() }

func (k *KeyURL) GetKeySecret() string { return k.url.Query().Get("secret") }

func (k *KeyURL) GetPeriod() string { return k.url.Query().Get("period") }

func (k *KeyURL) GetAlgorithm() string { return k.url.Query().Get("algorithm") }

func (k *KeyURL) GetDigits() string { return k.url.Query().Get("digits") }
