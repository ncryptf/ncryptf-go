package middleware

import (
	"github.com/ncryptf/ncryptf-go"
)

// EncryptionKeyDataContainer is a container for marshalling and unmarshalling data
type EncryptionKeyDataContainer struct {
	HashID           string
	KeyPairPublicKey []byte
	KeyPairSecretKey []byte
	SignKeyPublicKey []byte
	SignKeySecretKey []byte
}

// EncryptionKeyInterface and interfaces to represent an encryption key
type EncryptionKeyInterface interface {
	GetHashIdentifier() string
	GetBoxPublicKey() []byte
	GetBoxSecretKey() []byte
	GetBoxKeyPair() ncryptf.Keypair
	GetSignPublicKey() []byte
	GetSignSecretKey() []byte
	GetSignKeyPair() ncryptf.Keypair
	IsEphemeral() bool
	GetPublicKeyExpiration() int
	ExportContainer() *EncryptionKeyDataContainer
	InitFromData(hashID string, kpPk []byte, kpSk []byte, skPk []byte, skSk []byte) EncryptionKeyInterface
}
