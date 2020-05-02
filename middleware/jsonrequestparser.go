package middleware

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/eko/gocache/cache"
	"github.com/ncryptf/ncryptf-go"
	"github.com/vmihailenco/msgpack/v4"
)

var (
	// ErrUnableToDecryptRequest when the request body couldn't get decrypted
	ErrUnableToDecryptRequest = errors.New("Unable to decrypt request")
)

// JSONReuqestParser parses an incoming ncryptf request and converts it to Json
type JSONReuqestParser struct {
	cache        cache.CacheInterface
	contentTypes []string
	ek           EncryptionKeyInterface
}

// NewJSONReuqestParser provides an middleware to parse ncryptf requests
func NewJSONReuqestParser(cache cache.CacheInterface, key EncryptionKeyInterface) *JSONReuqestParser {
	return &JSONReuqestParser{
		cache: cache,
		contentTypes: []string{
			"application/vnd.25519+json",
			"application/vnd.ncryptf.json",
		},
		ek: key,
	}
}

// ServeHTTP *next
func (j *JSONReuqestParser) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	if j.checkHeader(r) {
		if b, err := ioutil.ReadAll(r.Body); err == nil {

			pubKey := r.Header.Get("x-pubkey")
			rawPubKey, _ := base64.StdEncoding.DecodeString(pubKey)
			if len(b) == 0 {
				ctx := r.Context()
				ctx = context.WithValue(ctx, "ncryptf-decrypted-body", "")
				ctx = context.WithValue(ctx, "ncryptf-version", 2)
				ctx = context.WithValue(ctx, "ncryptf-request-public-key", rawPubKey)

				next(rw, r.WithContext(ctx))
				return
			} else {
				if version, err := ncryptf.GetVersion(b); err == nil {
					if key, err := j.getEncryptionKey(r); err == nil {
						if txtResponse, err := j.decryptRequest(key, r, b, version); err == nil {
							ctx := r.Context()
							ctx = context.WithValue(ctx, "ncryptf-decrypted-body", txtResponse)
							ctx = context.WithValue(ctx, "ncryptf-version", version)
							if version == 2 {
								if pkk, err := ncryptf.GetPublicKeyFromResponse(b); err == nil {
									context.WithValue(ctx, "ncryptf-request-public-key", pkk)
								} else {
									http.Error(rw, http.StatusText(400), 400)
									return
								}
							} else {
								ctx = context.WithValue(ctx, "ncryptf-request-public-key", rawPubKey)
							}

							next(rw, r.WithContext(ctx))
							return
						}
					}
				}
			}
		}
	}

	http.Error(rw, http.StatusText(400), 400)
	return
}

func (j *JSONReuqestParser) decryptRequest(key EncryptionKeyInterface, r *http.Request, rawBody []byte, version int) (string, error) {
	if response, err := ncryptf.NewResponse(key.GetBoxSecretKey()); err == nil {
		var txtResponse string
		if version == 1 {
			publicKey := r.Header.Get("x-pubkey")
			nonce := r.Header.Get("x-nonce")

			if len(publicKey) == 0 || publicKey == "" || len(nonce) == 0 || nonce == "" {
				return "", ErrUnableToDecryptRequest
			}

			pk, err := base64.StdEncoding.DecodeString(publicKey)
			if err != nil {
				return "", ErrUnableToDecryptRequest
			}

			n, err := base64.StdEncoding.DecodeString(nonce)
			if err != nil {
				return "", ErrUnableToDecryptRequest
			}

			if txtResponse, err := response.DecryptWithPublicKeyAndNonce(rawBody, pk, n); err != nil {
				return txtResponse, nil
			}
		} else {
			if txtResponse, err := response.Decrypt(rawBody); err != nil {
				return txtResponse, nil
			}
		}

		if key.IsEphemeral() {
			hashKey := r.Header.Get("x-hashid")
			if len(hashKey) == 0 || hashKey == "" {
				return "", ErrUnableToDecryptRequest
			}

			j.cache.Delete(hashKey)
		}

		return txtResponse, nil
	}

	return "", ErrUnableToDecryptRequest
}

func (j *JSONReuqestParser) getEncryptionKey(r *http.Request) (EncryptionKeyInterface, error) {
	hashKey := r.Header.Get("x-hashid")
	if len(hashKey) == 0 || hashKey == "" {
		return nil, ErrUnableToDecryptRequest
	}

	if result, err := j.cache.Get(hashKey); err == nil {
		var key EncryptionKeyDataContainer
		err = msgpack.Unmarshal(result.([]byte), &key)
		if err != nil {
			return nil, ErrUnableToDecryptRequest
		}

		ki := j.ek.InitFromData(key.HashID, key.KeyPairPublicKey, key.KeyPairSecretKey, key.SignKeyPublicKey, key.SignKeySecretKey)

		return ki, nil
	}

	return nil, ErrUnableToDecryptRequest
}

func (j *JSONReuqestParser) checkHeader(r *http.Request) bool {
	for i := range j.contentTypes {
		if r.Header.Get("Content-Type") == j.contentTypes[i] {
			return true
		}
	}

	return false
}
