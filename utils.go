package ncryptf

import "github.com/jamesruan/sodium"

// Zero zeroes data on a given byte array
func Zero(data sodium.Bytes) bool {
	sodium.MemZero(data)
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}

// GenerateKeypair generates a crypto box keypair (32 byte secret, 32 byte public)
func GenerateKeypair() *Keypair {
	var kp = sodium.MakeBoxKP()

	key, err := NewKeypair(kp.SecretKey.Bytes, kp.PublicKey.Bytes)
	if err != nil {
		return nil
	}

	return key
}

// GenerateSigningKeypair generates a crypto sign keypair (64 byte secret, 32 byte public)
func GenerateSigningKeypair() *Keypair {
	var kp = sodium.MakeSignKP()

	key, err := NewKeypair(kp.SecretKey.Bytes, kp.PublicKey.Bytes)
	if err != nil {
		return nil
	}

	return key
}
