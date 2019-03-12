package ncryptf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jamesruan/sodium"
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

type jsonToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IKM          string `json:"ikm"`
	Signature    string `json:"signing"`
	ExpiresAt    int64  `json:"expires_at"`
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

func auth(t *testing.T) *Token {
	stack := ekb(t)
	url, token, kp := setup(t)
	sk := GenerateSigningKeypair()
	assert.NotNil(t, sk)

	client := &http.Client{}

	payload := "{\"email\":\"clara.oswald@example.com\",\"password\":\"c0rect h0rs3 b@tt3y st@Pl3\"}"

	request, err := NewRequest(kp.GetSecretKey(), sk.GetSecretKey())
	assert.Nil(t, err)

	pl, err := request.Encrypt(payload, stack.pubkey)
	assert.Nil(t, err)
	encryptedPayload := base64.StdEncoding.EncodeToString(pl)

	req, err := http.NewRequest("POST", url+"/authenticate", strings.NewReader(encryptedPayload))
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
		ja := jsonToken{}
		err = json.Unmarshal([]byte(message), &ja)
		assert.Nil(t, err)

		assert.NotEmpty(t, message)
		assert.NotEmpty(t, ja.AccessToken)
		assert.NotEmpty(t, ja.RefreshToken)
		assert.NotEmpty(t, ja.IKM)
		assert.NotEmpty(t, ja.Signature)
		assert.NotEmpty(t, ja.ExpiresAt)

		ikm, err := base64.StdEncoding.DecodeString(ja.IKM)
		assert.Nil(t, err)
		signature, err := base64.StdEncoding.DecodeString(ja.Signature)
		assert.Nil(t, err)

		return &Token{
			AccessToken:  ja.AccessToken,
			RefreshToken: ja.RefreshToken,
			IKM:          ikm,
			Signature:    signature,
			ExpiresAt:    ja.ExpiresAt}
	}

	t.Fail()
	return nil
}

func TestAuthenticateWithEncryptedRequest(t *testing.T) {
	token := auth(t)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.RefreshToken)
	assert.NotEmpty(t, token.IKM)
	assert.NotEmpty(t, token.Signature)
	assert.NotEmpty(t, token.ExpiresAt)
}

func TestAuthenticatedEchoWithEncryptedRequest(t *testing.T) {
	authToken := auth(t)
	assert.NotNil(t, authToken)

	stack := ekb(t)
	url, token, kp := setup(t)

	client := &http.Client{}

	payload := "{\"hello\":\"world\"}"

	request, err := NewRequest(kp.GetSecretKey(), authToken.Signature)
	assert.Nil(t, err)

	pl, err := request.Encrypt(payload, stack.pubkey)
	assert.Nil(t, err)
	encryptedPayload := base64.StdEncoding.EncodeToString(pl)

	req, err := http.NewRequest("PUT", url+"/echo", strings.NewReader(encryptedPayload))
	assert.Nil(t, err)

	req.Header.Set("Accept", "application/vnd.ncryptf+json")
	req.Header.Set("Content-Type", "application/vnd.ncryptf+json")
	req.Header.Set("X-HashId", stack.hashid)

	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}

	auth, err := NewAuthorization("PUT", "/echo", *authToken, time.Now(), payload, 2, nil)
	assert.Nil(t, err)

	req.Header.Set("Authorization", auth.GetHeader())

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

		/**
		 * As an added integrity check, the API will sign the message with the same key it issued during authentication
		 * Therefore, we can verify that the signing public key associated to the message matches the public key from the
		 * token we were issued.
		 *
		 * If the keys match, then we have assurance that the message is authenticated
		 * If the keys don't match, then the request has been tampered with and should be discarded.
		 *
		 * This check should ALWAYS be performed for authenticated requests as it ensures the validity of the message
		 * and the origin of the message.
		 */
		respSignPubKey, err := GetSigningPublicKeyFromResponse(responseBody)
		assert.Nil(t, err)

		signToken, err := authToken.GetSignaturePublicKey()
		assert.Nil(t, err)

		result := sodium.MemCmp(signToken, respSignPubKey, 32)
		assert.Equal(t, hex.EncodeToString(signToken), hex.EncodeToString(respSignPubKey), "Signing token hex matches")
		assert.Equal(t, 0, result, "Signing token matches")

		message, err := response.Decrypt(responseBody)
		assert.Nil(t, err)
		assert.Equal(t, payload, message, "Message and Payload are the same")
		return
	}

	t.Fail()
	return
}

func TestAuthenticatedEchoWithBadSignature(t *testing.T) {
	authToken := auth(t)
	assert.NotNil(t, authToken)

	sk := GenerateSigningKeypair()
	assert.NotNil(t, sk)

	stack := ekb(t)
	url, token, kp := setup(t)

	client := &http.Client{}

	payload := "{\"hello\":\"world\"}"

	request, err := NewRequest(kp.GetSecretKey(), sk.GetSecretKey())
	assert.Nil(t, err)

	pl, err := request.Encrypt(payload, stack.pubkey)
	assert.Nil(t, err)
	encryptedPayload := base64.StdEncoding.EncodeToString(pl)

	req, err := http.NewRequest("PUT", url+"/echo", strings.NewReader(encryptedPayload))
	assert.Nil(t, err)

	req.Header.Set("Accept", "application/vnd.ncryptf+json")
	req.Header.Set("Content-Type", "application/vnd.ncryptf+json")
	req.Header.Set("X-HashId", stack.hashid)

	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}

	auth, err := NewAuthorization("PUT", "/echo", *authToken, time.Now(), payload, 2, nil)
	assert.Nil(t, err)

	req.Header.Set("Authorization", auth.GetHeader())

	resp, err := client.Do(req)
	assert.Nil(t, err)

	assert.Equal(t, 401, resp.StatusCode, "Status is 401")
	defer resp.Body.Close()
}

func TestMalformedEncryptedRequest(t *testing.T) {
	sk := GenerateSigningKeypair()
	assert.NotNil(t, sk)

	stack := ekb(t)
	url, token, kp := setup(t)

	client := &http.Client{}

	payload := "{\"hello\":\"world\"}"

	request, err := NewRequest(kp.GetSecretKey(), sk.GetSecretKey())
	assert.Nil(t, err)

	pl, err := request.Encrypt(payload, stack.pubkey)
	copy(pl[60:96], "0")
	assert.Nil(t, err)
	encryptedPayload := base64.StdEncoding.EncodeToString(pl)

	req, err := http.NewRequest("PUT", url+"/echo", strings.NewReader(encryptedPayload))
	assert.Nil(t, err)

	req.Header.Set("Accept", "application/vnd.ncryptf+json")
	req.Header.Set("Content-Type", "application/vnd.ncryptf+json")
	req.Header.Set("X-HashId", stack.hashid)

	if token != "" {
		req.Header.Set("X-Access-Token", token)
	}

	resp, err := client.Do(req)
	assert.Nil(t, err)

	assert.Equal(t, 400, resp.StatusCode, "Status is 400")
	defer resp.Body.Close()
}
