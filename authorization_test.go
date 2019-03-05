package ncryptf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestV1HMAC(t *testing.T) {
	instance := NewInstance(t)

	for index, test := range instance.testCases {
		auth, err := NewAuthorization(test.method, test.uri, instance.token, instance.date, test.payload, 1, instance.salt)
		assert.Equal(t, nil, err, "Error is nil")

		header := instance.v1HMACHeaders[index]
		assert.Equal(t, header, auth.GetHeader(), "V1 Headers match")
		r := strings.Split(header, ",")
		hmac, err := base64.StdEncoding.DecodeString(r[1])
		assert.Equal(t, nil, err, "Error is nil")
		assert.Equal(t, false, auth.Verify(hmac, *auth, 90), "Verify fails")
	}
}

func TestV2HMAC(t *testing.T) {
	instance := NewInstance(t)

	for index, test := range instance.testCases {
		auth, err := NewAuthorization(test.method, test.uri, instance.token, instance.date, test.payload, 2, instance.salt)
		assert.Equal(t, nil, err, "Error is nil")

		header := instance.v2HMACHeaders[index]
		assert.Equal(t, header, auth.GetHeader(), "V2 Headers match")
		j, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(header, "HMAC ", ""))
		assert.Equal(t, nil, err, "Error is nil")
		ja := jsonAuthorization{}
		err = json.Unmarshal(j, &ja)
		assert.Equal(t, nil, err, "Error is nil")
		hmac, err := base64.StdEncoding.DecodeString(ja.hmac)
		assert.Equal(t, nil, err, "Error is nil")
		assert.Equal(t, false, auth.Verify(hmac, *auth, 90), "Verify fails")
	}
}

func TestVerify(t *testing.T) {
	instance := NewInstance(t)

	for _, test := range instance.testCases {
		auth, err := NewAuthorization(test.method, test.uri, instance.token, time.Now(), test.payload, 1, instance.salt)
		assert.Equal(t, nil, err, "Error is nil")

		assert.Equal(t, true, auth.Verify(auth.GetHMAC(), *auth, 90), "Verify succeeds")

		auth2, err2 := NewAuthorization(test.method, test.uri, instance.token, time.Now(), test.payload, 2, instance.salt)
		assert.Equal(t, nil, err2, "Error is nil")

		assert.Equal(t, true, auth2.Verify(auth2.GetHMAC(), *auth2, 90), "Verify succeeds")
	}
}