package ncryptf

import (
	"testing"

	"github.com/jamesruan/sodium"
	"github.com/stretchr/testify/assert"
)

type randomBytes struct {
	sodium.Bytes
}

func (k randomBytes) Size() int {
	return 32
}

func TestZero(t *testing.T) {
	data := randomBytes{}
	sodium.Randomize(&data)

	zero := Zero(data.Bytes)
	assert.Equal(t, true, zero, "Random bytes were zeroed")

	for i := 0; i < data.Length(); i++ {
		assert.Equal(t, uint8(0), data.Bytes[i], "Data element is 0")
	}
}

func TestKeypairGeneration(t *testing.T) {
	var kp = GenerateKeypair()
	assert.Equal(t, 32, len(kp.GetPublicKey()), "Public key is 32 bytes")
	assert.Equal(t, 32, len(kp.GetSecretKey()), "Secret key is 32 bytes")
}

func TestSigningKeypairGeneration(t *testing.T) {
	var kp = GenerateSigningKeypair()
	assert.Equal(t, 32, len(kp.GetPublicKey()), "Public key is 32 bytes")
	assert.Equal(t, 64, len(kp.GetSecretKey()), "Secret key is 64 bytes")
}
