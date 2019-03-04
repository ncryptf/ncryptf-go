package ncryptf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import (
	"errors"
	"time"

	"github.com/jamesruan/sodium"
)

var (
	// ErrTokenIKMSize an error when the IKM size not 32 bytes
	ErrTokenIKMSize = errors.New("Initial key material should be 32 bytes")

	// ErrTokenSignatureSize an error when the signature secret key is not 64 bytes
	ErrTokenSignatureSize = errors.New("Signature secret key should be 64 bytes")
)

// Token structure
type Token struct {
	accessToken  string
	refreshToken string
	ikm          sodium.Bytes
	signature    sodium.Bytes
	expiresAt    int64
}

// IsExpired returns true if the token is expired, and false otherwise
func (t *Token) IsExpired() bool {
	now := int64(time.Now().Unix())
	return now > t.expiresAt
}

// GetSignaturePublicKey retrieves the signature public key from the private componentz
func (t *Token) GetSignaturePublicKey() []byte {
	ssk := sodium.SignSecretKey{Bytes: t.signature}
	return ssk.ToBox().Bytes
}

// NewToken creates a token struct
func NewToken(accessToken string, refreshToken string, ikm []byte, signature []byte, expiresAt int64) (*Token, error) {
	if len(ikm) != 32 {
		return nil, ErrTokenIKMSize
	}

	if len(signature) != 64 {
		return nil, ErrTokenSignatureSize
	}

	return &Token{accessToken: accessToken, refreshToken: refreshToken, ikm: ikm, signature: signature, expiresAt: expiresAt}, nil
}
