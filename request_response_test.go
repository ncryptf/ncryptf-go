package ncryptf

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestV2EncryptDecrypt(t *testing.T) {

}

func TestDecryptWithEmptyString(t *testing.T) {

}

func TestV2EncryptDecryptWithEmptyPayload(t *testing.T) {

}

func TestV2DecryptWithSmallPayload(t *testing.T) {

}

func TestV1DecryptWithSmallPayload(t *testing.T) {

}

func TestV1EncryptDecrypt(t *testing.T) {
	d := NewRequestResponseData(t)

	request, err := NewRequest(d.clientKeyPairSecret, d.signatureKeyPairSecret)
	assert.Nil(t, err)

	cipher, err := request.EncryptWithNonce(d.payload, d.serverKeyPairPublic, 1, d.nonce)
	assert.Nil(t, err)

	signature, err := request.Sign(d.payload)
	assert.Nil(t, err)

	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	decrypted, err := response.DecryptWithPublicKeyAndNonce(cipher, d.clientKeyPairPublic, d.nonce)
	assert.Nil(t, err)

	eCipher := hex.EncodeToString(d.expectedCipher)
	aCipher := hex.EncodeToString(cipher)

	eSignature := hex.EncodeToString(d.expectedSignature)
	aSignature := hex.EncodeToString(signature)

	assert.Equal(t, eCipher, aCipher, "Ciphers match")
	assert.Equal(t, eSignature, aSignature, "Signatures match")

	assert.Equal(t, d.payload, decrypted, "Payloads match")

	isSignatureValid, err := IsSignatureValid(decrypted, signature, d.signatureKeyPairPublic)
	assert.Nil(t, err)

	assert.Equal(t, true, isSignatureValid, "Signature is valid")
}

func TestPublicKeyExtraction(t *testing.T) {
	d := NewRequestResponseData(t)

	publicKey, err := GetPublicKeyFromResponse(d.expectedv2Cipher)
	assert.Nil(t, err)
	assert.Equal(t, hex.EncodeToString(d.clientKeyPairPublic), hex.EncodeToString(publicKey))
}

func TestVersion(t *testing.T) {
	d := NewRequestResponseData(t)
	version, err := GetVersion(d.expectedCipher)
	assert.Nil(t, err)
	assert.Equal(t, 1, version, "Expected cipher is version 1")

	version, err = GetVersion(d.expectedv2Cipher)
	assert.Nil(t, err)
	assert.Equal(t, 2, version, "Expected cipher is version 2")
}
