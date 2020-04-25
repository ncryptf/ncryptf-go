package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ncryptf/ncryptf-go"
	"github.com/stretchr/testify/assert"
)

// @todo: Export from ncryptf/export_test.go
type TestCase struct {
	method  string
	uri     string
	payload string
}

func TestServeHttpV2(t *testing.T) {
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

	gtfas := func(accessString string) (ncryptf.Token, error) {
		var date = time.Now()

		ikm, _ := base64.StdEncoding.DecodeString("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=")

		signature, _ := base64.StdEncoding.DecodeString("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==")

		return ncryptf.Token{
			AccessToken:  "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J",
			RefreshToken: "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8",
			IKM:          ikm,
			Signature:    signature,
			ExpiresAt:    (date.Add(time.Hour * 4)).Unix()}, nil
	}

	guft := func(token ncryptf.Token) (interface{}, error) {
		return 1, nil
	}

	kp := ncryptf.GenerateKeypair()
	spk := ncryptf.GenerateSigningKeypair()
	nreq, _ := ncryptf.NewRequest(kp.GetSecretKey(), spk.GetSecretKey())

	for _, test := range testCases {
		cipher, _ := nreq.Encrypt(test.payload, spk.GetSecretKey())
		encryptedPayload := base64.StdEncoding.EncodeToString(cipher)
		req := httptest.NewRequest(
			test.method,
			"https://127.0.0.1/"+test.uri,
			strings.NewReader(encryptedPayload),
		)

		tkn, _ := gtfas("")
		auth, _ := ncryptf.NewAuthorization(
			test.method,
			test.uri,
			tkn,
			time.Now(),
			test.payload,
			2,
			nil,
		)

		req.Header.Set("Accept", "application/vnd.ncryptf+json")
		req.Header.Set("Content-Type", "application/vnd.ncryptf+json")
		req.Header.Set("Authorization", auth.GetHeader())
		req.Header.Set("X-Date", auth.GetDateString())
		authen := NewAuthentication(gtfas, guft)
		recorder := httptest.NewRecorder()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "application/json")
			return
		})

		authen.ServeHTTP(recorder, req, next)
		result := recorder.Result()
		assert.Equal(t, result.Header.Get("Status"), 200, "HTTP status is 200")
		fmt.Printf("%+v\n", result)
	}
}
