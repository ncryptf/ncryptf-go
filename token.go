package ncryptf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"errors"
	"time"
	"unsafe"
)

var (
	// ErrTokenIKMSize an error when the IKM size not 32 bytes
	ErrTokenIKMSize = errors.New("Initial key material should be 32 bytes")

	// ErrTokenSignatureSize an error when the signature secret key is not 64 bytes
	ErrTokenSignatureSize = errors.New("Signature secret key should be 64 bytes")
)

// Token structure
type Token struct {
	AccessToken  string
	RefreshToken string
	IKM          []byte
	Signature    []byte
	ExpiresAt    int64
}

// IsExpired returns true if the token is expired, and false otherwise
func (t *Token) IsExpired() bool {
	now := int64(time.Now().Unix())
	return now > t.ExpiresAt
}

// GetSignaturePublicKey retrieves the signature public key from the private componentz
func (t *Token) GetSignaturePublicKey() ([]byte, error) {
	publicKey := make([]byte, 32)
	db := bytePointer(t.Signature)
	result := int(C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(db)))

	if result == 0 {
		return publicKey, nil
	}

	return nil, ErrTokenSignatureSize
}

// NewToken creates a token struct
func NewToken(accessToken string, refreshToken string, ikm []byte, signature []byte, expiresAt int64) (*Token, error) {
	if len(ikm) != 32 {
		return nil, ErrTokenIKMSize
	}

	if len(signature) != 64 {
		return nil, ErrTokenSignatureSize
	}

	return &Token{AccessToken: accessToken, RefreshToken: refreshToken, IKM: ikm, Signature: signature, ExpiresAt: expiresAt}, nil
}
