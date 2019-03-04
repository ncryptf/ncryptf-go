package ncryptf

import (
	"errors"
)

var (
	// ErrKeypairSecretKeySize an error thrown when the secret key size is invalid
	ErrKeypairSecretKeySize = errors.New("ncryptf: Secret key should be a multiple of 16 bytes")

	// ErrKeypairPublicKeySize an error thrown when the public key size is invalid
	ErrKeypairPublicKeySize = errors.New("ncryptf: Public key should be a multiple of 4 bytes")
)

// Keypair structure
type Keypair struct {
	secretKey []byte
	publicKey []byte
}

// GetPublicKey returns the public component of the keypair
func (k *Keypair) GetPublicKey() []byte {
	return k.publicKey
}

// GetSecretKey returns the secret component of the keypair
func (k *Keypair) GetSecretKey() []byte {
	return k.secretKey
}

// NewKeypair function to create a new Keypair
func NewKeypair(secretKey []byte, publicKey []byte) (*Keypair, error) {
	if len(secretKey)%16 != 0 {
		return nil, ErrKeypairSecretKeySize
	}

	if len(publicKey)%4 != 0 {
		return nil, ErrKeypairPublicKeySize
	}

	return &Keypair{secretKey: secretKey, publicKey: publicKey}, nil
}
