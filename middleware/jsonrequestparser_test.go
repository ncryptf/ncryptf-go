package middleware

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ncryptf/ncryptf-go"
	"github.com/vmihailenco/msgpack/v4"

	"github.com/stretchr/testify/assert"
)

func TestJsonRequestParserServeHttp(t *testing.T) {
	var testCases = []TestCase{
		{"GET", "/api/v1/test", ""},
		{"GET", "/api/v1/test?foo=bar", ""},
		{"GET", "/api/v1/test?foo=bar&a[a]=1", ""},
		{"POST", "/api/v1/test", "{\"foo\":\"bar\"}"},
		{"POST", "/api/v1/test", "{\"foo\":1}"},
		{"POST", "/api/v1/test", "{\"foo\":false}"},
		{"POST", "/api/v1/test", "{\"foo\":1.023}"},
		{"DELETE", "/api/v1/test", "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}"},
		{"DELETE", "/api/v1/test?foo=bar", "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}"},
	}

	kp := ncryptf.GenerateKeypair()
	spk := ncryptf.GenerateSigningKeypair()
	cacheManager := GetCacheManager()
	for _, test := range testCases {
		// Test version 1 and 2
		for version := 1; version <= 2; version++ {
			ek := NewEncryptionKey()
			dataContainer := ek.ExportContainer()
			b, err := msgpack.Marshal(dataContainer)
			assert.Nil(t, err)

			payload, _ := strconv.Unquote(test.payload)

			cacheManager.Set(ek.GetHashIdentifier(), b, nil)

			nreq, err := ncryptf.NewRequest(kp.GetSecretKey(), spk.GetSecretKey())
			assert.Nil(t, err)

			cipher, err := nreq.EncryptWithVersion(payload, ek.GetBoxPublicKey(), version)
			assert.Nil(t, err)

			encryptedPayload := base64.StdEncoding.EncodeToString(cipher)
			nonce := base64.StdEncoding.EncodeToString(nreq.GetNonce())
			req := httptest.NewRequest(
				test.method,
				"https://127.0.0.1"+test.uri,
				strings.NewReader(encryptedPayload), // encryptedPayload will be "" for GET requests without a body
			)

			h := base64.StdEncoding.EncodeToString(kp.GetPublicKey())
			req.Header.Set("x-pubkey", h)
			req.Header.Set("Content-Type", "application/vnd.ncryptf.json")
			req.Header.Set("x-hashid", ek.GetHashIdentifier())
			if version == 1 {
				req.Header.Set("x-nonce", nonce)
			}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Header().Set("Content-Type", "application/json")

				ctx := r.Context()
				if test.payload != "" {
					ctxVersion, _ := ctx.Value("ncryptf-version").(int)
					ctxBody, _ := ctx.Value("ncryptf-decrypted-body").(string)
					ctxRequestPk, _ := ctx.Value("ncryptf-request-public-key").([]byte)
					assert.EqualValues(t, version, ctxVersion)
					assert.EqualValues(t, payload, ctxBody)
					assert.EqualValues(t, kp.GetPublicKey(), ctxRequestPk)
				}

				return
			})

			recorder := httptest.NewRecorder()

			requestParser := NewJSONReuqestParser(cacheManager, (*EncryptionKey)(nil))
			requestParser.ServeHTTP(recorder, req, next)
			result := recorder.Result()
			assert.Equal(t, result.StatusCode, 200, "HTTP status is 200")
		}
	}
}
