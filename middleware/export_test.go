package middleware

import (
	"crypto/rand"
	"time"
	"encoding/hex"
	"github.com/ncryptf/ncryptf-go"
	"github.com/eko/gocache/cache"
	"github.com/eko/gocache/store"
	"github.com/dgraph-io/ristretto"
)

type TestCase struct {
	method  string
	uri     string
	payload string
}

// EncryptionKey is an instance of EncryptionKeyInterface
type EncryptionKey struct {
	hashID string
	key ncryptf.Keypair
	signKey ncryptf.Keypair
}

// GetHashIdentifier returns the hash identifier
func (e *EncryptionKey) GetHashIdentifier() string {
	return e.hashID
}

// GetBoxPublicKey returns the crypto public key
func (e *EncryptionKey) GetBoxPublicKey() []byte {
	return e.key.GetPublicKey()
}

// GetBoxSecretKey returns the crypto secret key
func (e *EncryptionKey) GetBoxSecretKey() []byte {
	return e.key.GetSecretKey()
}

// GetBoxKeyPair returns the crypto keypair
func (e *EncryptionKey) GetBoxKeyPair() ncryptf.Keypair {
	return e.key
}

// GetSignPublicKey returns the public signing key
func (e *EncryptionKey) GetSignPublicKey() []byte {
	return e.signKey.GetPublicKey()
}

// GetSignSecretKey returns the secret signing key
func (e *EncryptionKey) GetSignSecretKey() []byte {
	return e.signKey.GetSecretKey()
}

// GetSignKeyPair returns the signing key pair
func (e *EncryptionKey) GetSignKeyPair() ncryptf.Keypair {
	return e.signKey
}

// IsEphemeral returns true if the key is ephemeral or not
func (e *EncryptionKey) IsEphemeral() bool {
	return false
}

// GetPublicKeyExpiration returns the public key expiration time
func (e *EncryptionKey) GetPublicKeyExpiration() int {
	var date = time.Now()

	return int((date.Add(time.Hour * 4)).Unix())
}

func (e *EncryptionKey) ExportContainer() *EncryptionKeyDataContainer {
	return &EncryptionKeyDataContainer{
		HashID: e.GetHashIdentifier(),
		KeyPairPublicKey: e.GetBoxPublicKey(),
		KeyPairSecretKey: e.GetBoxSecretKey(),
		SignKeyPublicKey: e.GetSignPublicKey(),
		SignKeySecretKey: e.GetSignSecretKey(),
	}
}

func (e *EncryptionKey) InitFromData(hashID string, kpPk []byte, kpSk []byte, skPk []byte, skSk []byte) EncryptionKeyInterface {
	kp, _ := ncryptf.NewKeypair(kpPk, kpSk)
	sk, _ := ncryptf.NewKeypair(skPk, skSk)
	return &EncryptionKey{
		hashID: hashID,
		key: *kp,
		signKey: *sk,
	}
}

// NewEncryptionKey generates a new encryption keypair
func NewEncryptionKey() *EncryptionKey {

	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		panic("Panic")
	}

	hashID := hex.EncodeToString(key)

	kp := ncryptf.GenerateKeypair()
	skp := ncryptf.GenerateSigningKeypair()

	return &EncryptionKey{
		hashID: hashID,
		key: *kp,
		signKey: *skp,
	}
}

func GetCacheManager() cache.CacheInterface {
	ristrettoCache, _ := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     100,
		BufferItems: 64,
	})
	ristrettoStore := store.NewRistretto(ristrettoCache, nil)

	cacheManager := cache.New(ristrettoStore)
	return cacheManager
}