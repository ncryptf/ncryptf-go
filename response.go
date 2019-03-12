package ncryptf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/jamesruan/sodium"
)

// Response structure for response instance
type Response struct {
	secretKey []byte
}

var (
	// ErrResponseSecretKeyLength an error for when the secret key length is invalid
	ErrResponseSecretKeyLength = fmt.Errorf("Secret key should be %d bytes", C.crypto_box_SECRETKEYBYTES)

	// ErrResponseMACLength an error when the message length is invalid
	ErrResponseMACLength = fmt.Errorf("Message should be longer than %d bytes", C.crypto_box_MACBYTES)

	// ErrResponseNotSuitableForPublicKeyExtraction an error for when the public key cannot be extracted from the response
	ErrResponseNotSuitableForPublicKeyExtraction = errors.New("The response provided is not suitable for public key extraction")

	// ErrResponseMessageLength an error when the response message length is invalid
	ErrResponseMessageLength = errors.New("The response message is too short")

	// ErrRresponseSignatureLength an error when the signature length is invalid
	ErrRresponseSignatureLength = fmt.Errorf("Signature should be %d bytes", 64)

	// ErrResponsePublicKeyLength an error when the public key length is invalid
	ErrResponsePublicKeyLength = fmt.Errorf("Public key should be %d bytes", C.crypto_sign_PUBLICKEYBYTES)

	// ErrResponseSignatureVerification an error when signature verification fails
	ErrResponseSignatureVerification = errors.New("Signature verification failed")

	// ErrResponseNonceLength an error when the nonce length is invalid
	ErrResponseNonceLength = fmt.Errorf("Nonce should be %d bytes", C.crypto_box_NONCEBYTES)

	// ErrResponseDecryptionFailed an error when decryption failed
	ErrResponseDecryptionFailed = errors.New("Unable to decrypt message")

	// ErrResponseInvalidChecksum an error when the checksum associated with a message is invalid
	ErrResponseInvalidChecksum = errors.New("The checksum associated with the message is not valid")
)

// Decrypt decrypts a v2 message with an embedded public key
func (r *Response) Decrypt(response []byte) (string, error) {
	if len(response) < 236 {
		return "", ErrResponseMessageLength
	}

	nonce := response[4:28]

	return r.decrypt(response, nil, nonce)
}

// DecryptWithPublicKey decrypts a response with a given public key. Used for v1 signatures
func (r *Response) DecryptWithPublicKey(response []byte, publicKey []byte) (string, error) {
	if len(response) < 236 {
		return "", ErrResponseMessageLength
	}

	nonce := response[4:28]

	return r.decrypt(response, publicKey, nonce)
}

// DecryptWithPublicKeyAndNonce decrypts a message with a public key and nonce
func (r *Response) DecryptWithPublicKeyAndNonce(response []byte, publicKey []byte, nonce []byte) (string, error) {
	return r.decrypt(response, publicKey, nonce)
}

// decrypt an internal method to decrypt a message
func (r *Response) decrypt(response []byte, publicKey []byte, nonce []byte) (string, error) {
	if len(nonce) != C.crypto_box_NONCEBYTES {
		return "", ErrResponseNonceLength
	}

	version, err := GetVersion(response)
	if err != nil {
		return "", err
	}

	if version == 2 {
		/**
		 * Payload should be a minimum of 236 bytes
		 * 4 byte header
		 * 24 byte nonce
		 * 32 byte public key
		 * 16 byte Box.MACBYTES
		 * 32 byte signature public key
		 * 64 byte signature
		 * 64 byte checksum
		 */
		responseLength := len(response)
		if responseLength < 236 {
			return "", ErrResponseMessageLength
		}

		payload := response[0 : responseLength-64]
		checksum := response[responseLength-64 : responseLength]

		db := bytePointer(payload)
		calculatedChecksum := make([]byte, 64)

		if int(C.crypto_generichash(
			(*C.uchar)(unsafe.Pointer(&calculatedChecksum[0])),
			C.size_t(len(calculatedChecksum)),
			(*C.uchar)(unsafe.Pointer(db)),
			C.ulonglong(len(payload)),
			(*C.uchar)(unsafe.Pointer(&nonce[0])),
			C.size_t(len(nonce)))) != 0 {
			return "", ErrResponseDecryptionFailed
		}

		if sodium.MemCmp(checksum, calculatedChecksum, 64) != 0 {
			return "", ErrResponseInvalidChecksum
		}

		publicKey = response[28:60]
		payloadLength := len(payload)
		signature := payload[payloadLength-64 : payloadLength]
		sigPubKey := payload[payloadLength-96 : payloadLength-64]
		body := payload[60 : payloadLength-96]

		decryptedPayload, err := r.decryptBody(body, publicKey, nonce)
		if err != nil {
			return "", err
		}

		sigCheck, err := IsSignatureValid(decryptedPayload, signature, sigPubKey)
		if err != nil || sigCheck == false {
			return "", err
		}

		return decryptedPayload, nil
	}

	if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
		return "", ErrResponsePublicKeyLength
	}

	return r.decryptBody(response, publicKey, nonce)
}

// decryptBody an internal method to decrypt a message body
func (r *Response) decryptBody(response []byte, publicKey []byte, nonce []byte) (string, error) {
	if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
		return "", ErrResponsePublicKeyLength
	}

	if len(nonce) < C.crypto_box_NONCEBYTES {
		return "", ErrResponseNonceLength
	}

	if len(response) < C.crypto_box_MACBYTES {
		return "", ErrResponseMessageLength
	}

	message := make([]byte, len(response)-C.crypto_box_MACBYTES)
	m := bytePointer(message)
	db := bytePointer(response)

	if int(C.crypto_box_open_easy(
		(*C.uchar)(m),
		(*C.uchar)(unsafe.Pointer(db)),
		C.ulonglong(len(response)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&r.secretKey[0]),
	)) == 0 {
		return string(message), nil
	}

	return "", ErrResponseDecryptionFailed
}

// IsSignatureValid returns true if the detached signature associated to the message is valid or not
func IsSignatureValid(response string, signature []byte, publicKey []byte) (bool, error) {
	if len(signature) != 64 {
		return false, ErrRresponseSignatureLength
	}

	if len(publicKey) != C.crypto_sign_PUBLICKEYBYTES {
		return false, ErrResponsePublicKeyLength
	}

	message := []byte(response)
	db := bytePointer(message)

	result := int(C.crypto_sign_verify_detached(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(db)),
		C.ulonglong(len(message)),
		(*C.uchar)(&publicKey[0])))

	if result == 0 {
		return true, nil
	}

	return false, ErrResponseSignatureVerification
}

// GetPublicKeyFromResponse Returns the public key from a v2 response
func GetPublicKeyFromResponse(response []byte) ([]byte, error) {
	version, err := GetVersion(response)
	if err != nil || version == -1 {
		return nil, err
	}

	if version == 2 {
		if len(response) < 236 {
			return nil, ErrResponseMessageLength
		}

		return response[28:60], nil
	}

	return nil, ErrResponseNotSuitableForPublicKeyExtraction
}

// GetSigningPublicKeyFromResponse Extracts the siging public key from a v3 response
func GetSigningPublicKeyFromResponse(response []byte) ([]byte, error) {
	version, err := GetVersion(response)
	if err != nil {
		return nil, err
	}

	if version == 2 {
		messageLength := len(response)
		if messageLength < 236 {
			return nil, ErrResponseMessageLength
		}

		return response[messageLength-160 : (messageLength - 160 + 32)], nil
	}

	return nil, ErrResponseNotSuitableForPublicKeyExtraction
}

// GetVersion returns the version associated with a given message
func GetVersion(response []byte) (int, error) {
	if len(response) < C.crypto_box_MACBYTES {
		return -1, ErrResponseMACLength
	}

	header := response[0:4]
	hex := strings.ToUpper(hex.EncodeToString(header))

	if hex == "DE259002" {
		return 2, nil
	}

	return 1, nil
}

// NewResponse returns a new response object or error
func NewResponse(secretKey []byte) (*Response, error) {
	if len(secretKey) != C.crypto_box_SECRETKEYBYTES {
		return nil, ErrResponseSecretKeyLength
	}

	return &Response{secretKey: secretKey}, nil
}
