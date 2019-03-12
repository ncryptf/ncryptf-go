package ncryptf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestV2EncryptDecrypt(t *testing.T) {
	d := NewRequestResponseData(t)
	request, err := NewRequest(d.clientKeyPairSecret, d.signatureKeyPairSecret)
	assert.Nil(t, err)

	cipher, err := request.EncryptWithNonce(d.payload, d.serverKeyPairPublic, 2, d.nonce)
	assert.Nil(t, err)

	eCipher := hex.EncodeToString(d.expectedv2Cipher)
	aCipher := hex.EncodeToString(cipher)
	assert.Equal(t, eCipher, aCipher, "Ciphers match")

	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	decrypted, err := response.Decrypt(cipher)
	assert.Nil(t, err)
	assert.Equal(t, d.payload, decrypted, "Decrypted message matches payload")
}

func TestDecryptWithEmptyString(t *testing.T) {
	d := NewRequestResponseData(t)
	request, err := NewRequest(d.clientKeyPairSecret, d.signatureKeyPairSecret)
	assert.Nil(t, err)

	cipher, err := request.Encrypt("", d.serverKeyPairPublic)
	assert.Nil(t, err)

	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	decrypted, err := response.Decrypt(cipher)
	assert.Nil(t, err)
	assert.Equal(t, "", decrypted, "Decrypted message matches payload")
}

func TestV2EncryptDecryptWithEmptyPayload(t *testing.T) {
	d := NewRequestResponseData(t)
	request, err := NewRequest(d.clientKeyPairSecret, d.signatureKeyPairSecret)
	assert.Nil(t, err)

	cipher, err := request.EncryptWithNonce("", d.serverKeyPairPublic, 2, d.nonce)
	assert.Nil(t, err)

	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	decrypted, err := response.Decrypt(cipher)
	assert.Nil(t, err)
	assert.Equal(t, "", decrypted, "Decrypted message matches payload")
}

func TestV2DecryptWithSmallPayload(t *testing.T) {
	header, err := hex.DecodeString("DE259002")
	assert.Nil(t, err)
	var stream bytes.Buffer
	stream.Write(header)
	stream.Write(make([]byte, 231))

	cipher := stream.Bytes()
	d := NewRequestResponseData(t)
	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	message, err := response.DecryptWithPublicKey(cipher, d.clientKeyPairPublic)
	assert.Equal(t, "", message, "Message is empty")
	assert.NotNil(t, err)
}

func TestV1DecryptWithSmallPayload(t *testing.T) {
	d := NewRequestResponseData(t)
	cipher := make([]byte, 15)

	response, err := NewResponse(d.serverKeyPairSecret)
	assert.Nil(t, err)

	result, err := response.DecryptWithPublicKey(cipher, d.clientKeyPairPublic)
	assert.Equal(t, "", result, "Result is empty")
	assert.NotNil(t, err)
	assert.Equal(t, ErrResponseMessageLength, err, "Errors are equal")
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
