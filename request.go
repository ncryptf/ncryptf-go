package ncryptf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	"github.com/jamesruan/sodium"
)

// Request struct
type Request struct {
	secretKey          []byte
	signatureSecretKey []byte
	nonce              []byte
}

var (
	// ErrRequestSign an error for when signing fails
	ErrRequestSign = errors.New("Unable to sign request")

	// ErrRequestSecretKeyLength an error for when the secret key length is not correct
	ErrRequestSecretKeyLength = fmt.Errorf("Secret key should be %d bytes", C.crypto_box_SECRETKEYBYTES)

	// ErrRequestSignatureKeyLength an error for when the signature key length is not correct
	ErrRequestSignatureKeyLength = fmt.Errorf("Signature key should be %d bytes", C.crypto_sign_SECRETKEYBYTES)

	// ErrRequestPublicKeyLength an error for when the public key length is not correct
	ErrRequestPublicKeyLength = fmt.Errorf("Public key should be %d bytes", C.crypto_box_PUBLICKEYBYTES)

	// ErrRequestNonceLength an error when the nonce isn't the correct length
	ErrRequestNonceLength = fmt.Errorf("Nonce should be %d bytes", C.crypto_box_NONCEBYTES)

	// ErrRequestEncyptionFailed an error when encryption fails
	ErrRequestEncyptionFailed = errors.New("An error occured when encrypting the data")
)

// Encrypt a data string with a given public key using v2 and a generated nonce
func (r *Request) Encrypt(data string, publicKey []byte) ([]byte, error) {
	return r.EncryptWithVersion(data, publicKey, 2)
}

// EncryptWithVersion encrypts a data string with a given public key, a generated nonce, and a specified version
func (r *Request) EncryptWithVersion(data string, publicKey []byte, version int) ([]byte, error) {
	nonce := sodium.BoxNonce{}
	sodium.Randomize(&nonce)

	return r.EncryptWithNonce(data, publicKey, version, nonce.Bytes)
}

// EncryptWithNonce encrypts a data string with a given public key, and a specified nonce and version
func (r *Request) EncryptWithNonce(data string, publicKey []byte, version int, nonce []byte) ([]byte, error) {

	if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
		return nil, ErrRequestPublicKeyLength
	}

	if len(nonce) != C.crypto_box_NONCEBYTES {
		return nil, ErrRequestNonceLength
	}

	r.nonce = nonce

	if version == 2 {
		header, err := hex.DecodeString("DE259002")
		if err != nil {
			return nil, ErrRequestEncyptionFailed
		}

		body, err := r.encryptBody(data, publicKey, nonce)
		if err != nil {
			return nil, err
		}

		if body == nil {
			return nil, ErrRequestEncyptionFailed
		}

		iPublicKey := make([]byte, 32)
		if int(C.crypto_scalarmult_base(
			(*C.uchar)(&iPublicKey[0]),
			(*C.uchar)(&r.secretKey[0]))) != 0 {
			return nil, ErrRequestEncyptionFailed
		}

		sigPubKey := make([]byte, 32)
		if int(C.crypto_sign_ed25519_sk_to_pk(
			(*C.uchar)(&sigPubKey[0]),
			(*C.uchar)(&r.signatureSecretKey[0]))) != 0 {
			return nil, ErrRequestEncyptionFailed
		}
		signature, err := r.Sign(data)
		if err != nil {
			return nil, err
		}

		var stream bytes.Buffer
		stream.Write(header)
		stream.Write(nonce)
		stream.Write(iPublicKey)
		stream.Write(body)
		stream.Write(sigPubKey)
		stream.Write(signature)

		payload := stream.Bytes()

		checksum := make([]byte, 64)
		db := bytePointer(payload)

		if int(C.crypto_generichash(
			(*C.uchar)(unsafe.Pointer(&checksum[0])),
			64,
			(*C.uchar)(unsafe.Pointer(db)),
			C.ulonglong(len(payload)),
			(*C.uchar)(unsafe.Pointer(&r.nonce[0])),
			C.size_t(len(r.nonce)))) == 0 {
			stream.Write(checksum)
			return stream.Bytes(), nil
		}

		return nil, ErrRequestEncyptionFailed
	}

	return r.encryptBody(data, publicKey, nonce)
}

func (r *Request) encryptBody(data string, publicKey []byte, nonce []byte) ([]byte, error) {

	if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
		return nil, ErrRequestPublicKeyLength
	}

	if len(nonce) != C.crypto_box_NONCEBYTES {
		return nil, ErrRequestNonceLength
	}

	message := []byte(data)
	db := bytePointer(message)
	cipher := make([]byte, C.crypto_box_MACBYTES+len(message))

	if int(C.crypto_box_easy(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		(*C.uchar)(unsafe.Pointer(db)),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&r.nonce[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&r.secretKey[0])))) == 0 {
		return cipher, nil
	}

	return nil, ErrRequestEncyptionFailed
}

// Sign signs the data
func (r *Request) Sign(data string) ([]byte, error) {
	signature := make([]byte, C.crypto_sign_BYTES)
	message := []byte(data)
	db := bytePointer(message)

	if int(C.crypto_sign_detached(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(db)),
		C.ulonglong(len(message)),
		(*C.uchar)(&r.signatureSecretKey[0]))) == 0 {
		return signature, nil
	}

	return nil, ErrRequestSign
}

// GetNonce returns a 24 byte nonce
func (r *Request) GetNonce() []byte {
	return r.nonce
}

// NewRequest returns a new request instance
func NewRequest(secretKey []byte, signatureSecretKey []byte) (*Request, error) {
	if len(secretKey) != C.crypto_box_SECRETKEYBYTES {
		return nil, ErrRequestSecretKeyLength
	}

	if len(signatureSecretKey) != C.crypto_sign_SECRETKEYBYTES {
		return nil, ErrRequestSignatureKeyLength
	}

	return &Request{secretKey: secretKey, signatureSecretKey: signatureSecretKey, nonce: nil}, nil
}
