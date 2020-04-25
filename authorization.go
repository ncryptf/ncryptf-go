package ncryptf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/jamesruan/sodium"
)

var (
	// ErrAuthorizationKeySize an error when the key cannot be extracted
	ErrAuthorizationKeySize = errors.New("Unable to extract key material")

	// ErrNonDecipherableHMACHeader an error when the HMAC header can't be parsed
	ErrNonDecipherableHMACHeader = errors.New("HMAC header could not be deciphered")
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
	return a.date.UTC().Format(time.RFC1123Z)
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
		json := "{\"access_token\":\"" + a.token.AccessToken + "\",\"date\":\"" + a.GetDateString() + "\",\"hmac\":\"" + hmac + "\",\"salt\":\"" + salt + "\",\"v\":2}"
		json = strings.Replace(json, "/", "\\/", -1)
		return "HMAC " + base64.StdEncoding.EncodeToString([]byte(json))
	}

	return "HMAC " + a.token.AccessToken + "," + hmac + "," + salt
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

// NewAuthorizationFromString Returns a jsonAuthorization object from an HMAC header
func NewAuthorizationFromString(hmacHeader string) (*jsonAuthorization, error) {
	if hmacHeader == "" {
		return nil, ErrNonDecipherableHMACHeader
	}

	r, _ := regexp.Compile(`^HMAC\s+(...+)$`)

	matches := r.FindStringSubmatch(hmacHeader)

	if strings.Contains(matches[1], ",") {
		params := strings.Split(matches[1], ",")

		if len(params) != 3 {
			return nil, ErrNonDecipherableHMACHeader
		}

		// Generate a token structure with bogus data
		return &jsonAuthorization{
			AccessToken: params[0],
			Hmac:        params[1],
			Salt:        params[2],
			Version:     1,
			Date:        ""}, nil
	} else {
		d, err := base64.StdEncoding.DecodeString(matches[1])
		if err != nil {
			return nil, ErrNonDecipherableHMACHeader
		}

		var params jsonAuthorization
		err = json.Unmarshal(d, &params)

		if err == nil {
			return &params, nil
		}

	}

	return nil, ErrNonDecipherableHMACHeader
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
	hkdf := hkdf.New(sha256.New, token.IKM, salt, []byte(AuthInfo))
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
