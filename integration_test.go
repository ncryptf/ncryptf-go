package ncryptf

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ephemeralKeyBootstrap struct {
	pubkey  []byte
	hashid  string
	message string
}

type jsonEKB struct {
	Public    string
	Signature string
	Hash      string `json:"hash-id"`
}

func setup(t *testing.T) (string, string, *Keypair) {
	if os.Getenv("NCRYPTF_TEST_API") == "" {
		t.Skip("Required environment variables are not defined")
		return "", "", nil
	}

	kp := GenerateKeypair()
	return os.Getenv("NCRYPTF_TEST_API"), os.Getenv("ACCESS_TOKEN"), kp
}

func ekb(t *testing.T) *ephemeralKeyBootstrap {
	url, token, kp := setup(t)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url+"/ek", nil)
	assert.Nil(t, err)
	req.Header.Set("Accept", "application/vnd.ncryptf+json")
	req.Header.Set("Content-Type", "application/vnd.ncryptf+json")

	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}

	req.Header.Set("x-pubkey", base64.StdEncoding.EncodeToString(kp.GetPublicKey()))

	resp, err := client.Do(req)
	assert.Nil(t, err)

	assert.Equal(t, 200, resp.StatusCode, "Status is 200")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		assert.Nil(t, err)
		bodyString := string(bodyBytes)

		response, err := NewResponse(kp.GetSecretKey())
		assert.Nil(t, err)
		responseBody, err := base64.StdEncoding.DecodeString(bodyString)
		assert.Nil(t, err)

		message, err := response.Decrypt(responseBody)
		assert.Nil(t, err)

		ja := jsonEKB{}
		err = json.Unmarshal([]byte(message), &ja)
		assert.Nil(t, err)

		assert.NotEmpty(t, message)
		assert.NotEmpty(t, ja.Public)
		assert.NotEmpty(t, ja.Hash)
		assert.NotEmpty(t, ja.Signature)

		pubkey, err := GetPublicKeyFromResponse(responseBody)
		assert.Nil(t, err)
		return &ephemeralKeyBootstrap{
			pubkey:  pubkey,
			hashid:  resp.Header["X-Hashid"][0],
			message: message}
	}

	t.Fail()
	return nil
}

func TestEphemeralKeyBootstrap(t *testing.T) {
	stack := ekb(t)
	assert.NotNil(t, stack)
}

func TestUnauthenticatedEncryptedRequest(t *testing.T) {
	stack := ekb(t)
	url, token, kp := setup(t)
	sk := GenerateSigningKeypair()
	assert.NotNil(t, sk)

	client := &http.Client{}

	payload := "{\"hello\":\"world\"}"

	request, err := NewRequest(kp.GetSecretKey(), sk.GetSecretKey())
	assert.Nil(t, err)

	pl, err := request.Encrypt(payload, stack.pubkey)
	assert.Nil(t, err)
	encryptedPayload := base64.StdEncoding.EncodeToString(pl)

	req, err := http.NewRequest("POST", url+"/echo", strings.NewReader(encryptedPayload))
	assert.Nil(t, err)

	req.Header.Set("Accept", "application/vnd.ncryptf+json")
	req.Header.Set("Content-Type", "application/vnd.ncryptf+json")
	req.Header.Set("X-HashId", stack.hashid)

	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}

	resp, err := client.Do(req)
	assert.Nil(t, err)

	assert.Equal(t, 200, resp.StatusCode, "Status is 200")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		assert.Nil(t, err)
		bodyString := string(bodyBytes)

		response, err := NewResponse(kp.GetSecretKey())
		assert.Nil(t, err)
		responseBody, err := base64.StdEncoding.DecodeString(bodyString)
		assert.Nil(t, err)

		message, err := response.Decrypt(responseBody)
		assert.Nil(t, err)
		assert.Equal(t, payload, message, "Payload matches decrypted message")
		return
	}

	t.Fail()
}
