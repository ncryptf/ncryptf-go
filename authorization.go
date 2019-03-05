package ncryptf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/jamesruan/sodium"
)

var (
	// ErrAuthorizationKeySize an error when the key cannot be extracted
	ErrAuthorizationKeySize = errors.New("Unable to extract key material")
)

// AuthInfo INFO parameter for HMAC
const AuthInfo = "HMAC|AuthenticationKey"

// Authorization struct
type Authorization struct {
	token     Token
	salt      []byte
	date      time.Time
	signature string
	hmac      []byte
	version   int
}

// GetDate returns the authorization date
func (a *Authorization) GetDate() time.Time {
	return a.date
}

// GetDateString returns the formatted date string
func (a *Authorization) GetDateString() string {
	return a.date.UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000")
}

// GetHMAC returns the HMAC byte array
func (a *Authorization) GetHMAC() []byte {
	return a.hmac
}

// GetEncodedHMAC returns the base64 encoded HMAC
func (a *Authorization) GetEncodedHMAC() string {
	return base64.StdEncoding.EncodeToString(a.hmac)
}

// GetEncodedSalt returns the base64 encoded salt
func (a *Authorization) GetEncodedSalt() string {
	return base64.StdEncoding.EncodeToString(a.salt)
}

// GetSignatureString returns the generated signature string
func (a *Authorization) GetSignatureString() string {
	return a.signature
}

// GetHeader returns the formatted header
func (a *Authorization) GetHeader() string {
	salt := a.GetEncodedSalt()
	hmac := a.GetEncodedHMAC()

	if a.version == 2 {
		json := "{\"access_token\":\"" + a.token.accessToken + "\",\"date\":\"" + a.GetDateString() + "\",\"hmac\":\"" + hmac + "\",\"salt\":\"" + salt + "\",\"v\":2}"
		json = strings.Replace(json, "/", "\\/", -1)
		return "HMAC " + base64.StdEncoding.EncodeToString([]byte(json))
	}

	return "HMAC " + a.token.accessToken + "," + hmac + "," + salt
}

// Verify returns true if the provided hmac, authorixzation, and drift allowance is acceptable
func (a *Authorization) Verify(hmac []byte, auth Authorization, driftAllowance int) bool {
	drift := a.getTimeDrift(a.GetDate())

	if drift >= driftAllowance {
		return false
	}

	if sodium.MemCmp(hmac, a.GetHMAC(), 32) == 0 {
		return true
	}

	return false
}

// GetTimeDrift Returns the drift time between the current time and the provided date
func (a *Authorization) getTimeDrift(date time.Time) int {
	now := time.Now()

	return int(math.Abs(float64(now.Unix() - date.Unix())))
}

// NewAuthorization generates a new Authorization struct from the provided data
func NewAuthorization(httpMethod string, uri string, token Token, date time.Time, payload string, version int, salt []byte) (*Authorization, error) {
	httpMethod = strings.ToUpper(httpMethod)

	if salt == nil {
		data := randomBytes{}
		sodium.Randomize(&data)
		salt = data.Bytes
	}

	signature := Derive(httpMethod, uri, salt, date, payload, version)
	hkdf := hkdf.New(sha256.New, token.ikm, salt, []byte(AuthInfo))
	hkdfBytes := streamToBytes(hkdf)

	if hkdfBytes == nil {
		return nil, ErrAuthorizationKeySize
	}

	hkdfString := hex.EncodeToString(hkdfBytes)

	key := []byte(strings.ToLower(hkdfString))
	sig := []byte(signature)
	h := hmac.New(sha256.New, key)
	h.Write(sig)

	return &Authorization{token: token, salt: salt, date: date, signature: signature, hmac: h.Sum(nil), version: version}, nil
}

// Helper function to get first 32 bytes of HMAC
func streamToBytes(stream io.Reader) []byte {
	out := make([]byte, 32)

	n, err := io.ReadFull(stream, out)
	if n != 32 || err != nil {
		return nil
	}

	return out
}
