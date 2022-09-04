package tempotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var errValidateLength error = errors.New("missing length")

var nopads32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateURLQR(otp OTP, key32 string) (*KeyURL, error) {
	// set otp secret url for client (account), otpauth://TYPE/LABEL?PARAMETERS
	// [SCHEME]://totp/[ISSUER]:joe@gmail.com?key=[OTPSecret32]&issuer=[ISSUER]&period=[PERIOD]
	qVals := url.Values{}
	qVals.Set("secret", key32)
	qVals.Set("issuer", otp.Issuer)
	qVals.Set("period", strconv.FormatUint(uint64(otp.Period), 10))
	qVals.Set("algorithm", otp.Algorithm.String())
	qVals.Set("digits", otp.Digits.String())
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + otp.Issuer + ":" + otp.Account,
		RawQuery: qVals.Encode(),
	}

	return NewTotpURL(u.String())
}

// TOTP is a HOTP Token seeded with every n-seconds.
func GenerateTOTPToken(size uint) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return nopads32.EncodeToString(buffer), nil
}

func GenerateKeySecret(otp OTP) string {
	if len(otp.KeySecret) == 0 {
		secret, err := GenerateTOTPToken(otp.KeySize)
		if err != nil {
			return ""
		}
		return secret
	}

	return strings.ToUpper(nopads32.EncodeToString(otp.KeySecret))
}

func GenerateHOTP(secret string, digits uint, limit uint64) string {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}
	secret = strings.ToUpper(secret)

	secretbytes, _ := base32.StdEncoding.DecodeString(secret)

	tokens := make([]byte, 8)
	binary.BigEndian.PutUint64(tokens, uint64(limit))
	hash := hmac.New(AlgorithmSHA1.Hash, secretbytes)
	hash.Write(tokens)
	h := hash.Sum(nil)

	// Take a subset of generated hash to create an otp.
	// HMAC-SHA1 results 20 bytes with max index is 19.
	// Then truncate it to 4 bytes.
	// This number will determine which index to start from.
	// https://www.rfc-editor.org/rfc/rfc4226#section-5.4
	offset := h[len(h)-1] & 0xF
	value := int64(((int(h[offset]) & 0x7F) << 24) |
		((int(h[offset+1] & 0xFF)) << 16) |
		((int(h[offset+2] & 0xFF)) << 8) |
		(int(h[offset+3]) & 0xFF))

	mod := int32(value % int64(math.Pow10(int(digits))))

	return fmt.Sprint(mod)
}

// Generate 6 Digit OTP
func GenerateOTP(otp OTP, secretkey string) string {
	// this limit will become a comparator
	limit := time.Now().Unix() / int64(otp.Period)

	// generate and signing value with 6 digit otp
	otptoken := GenerateHOTP(secretkey, uint(otp.Digits), uint64(limit))
	return otptoken
}

func HOTPVerify(otp string, limit uint64, secretkey string) (bool, error) {
	otp = strings.TrimSpace(otp)
	if len(otp) != int(DigitSix) {
		return false, errValidateLength
	}

	digit, _ := strconv.Atoi(DigitSix.String())
	generatedotp := GenerateHOTP(secretkey, uint(digit), limit)
	if subtle.ConstantTimeCompare([]byte(generatedotp), []byte(otp)) == 1 {
		return true, nil
	}

	return false, nil
}

func Validating(validation OTPValidation) (bool, error) {
	limits := []uint64{}
	// limit := int64(math.Floor(float64(time.Now().UTC().Unix()) / float64(1800)))
	limit := time.Now().Unix() / int64(2*30)

	limits = append(limits, uint64(limit))
	for i := 1; i <= int(1); i++ { // >>> skew before after
		limits = append(limits, uint64(limit+int64(i)))
		limits = append(limits, uint64(limit-int64(i)))
	}

	fmt.Println("VALIDATING LIMITS : ", limits)
	println()
	for _, limit := range limits {
		fmt.Println("VALIDATING per LIMIT : ", limit)
		isvalid, err := HOTPVerify(validation.Passcode, limit, validation.KeySecret)
		if err != nil {
			return false, err
		}
		if isvalid {
			return true, nil
		}
	}

	return false, nil
}

func ValidateOTP(passcode string, secret string) map[string]interface{} {
	// this otp string can be replaced by struct
	var validation OTPValidation = OTPValidation{
		Passcode:  passcode,
		KeySecret: secret,
	}

	//Validate HOTP
	isvalid, err := Validating(validation)
	if err != nil {
		return nil
	}

	response := map[string]interface{}{
		"Status":  200,
		"Message": "OTP has been verified successfully",
		"VerificationResponse": map[string]interface{}{
			"Valid": isvalid,
		},
	}

	return response

}
