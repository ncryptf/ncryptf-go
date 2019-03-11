package ncryptf

import "github.com/jamesruan/sodium"

type randomBytes struct {
	sodium.Bytes
}

func (k randomBytes) Size() int {
	return 32
}

type jsonAuthorization struct {
	AccessToken string `json:"access_token"`
	Date        string
	Hmac        string
	Salt        string
}

func bytePointer(b []byte) *uint8 {
	if len(b) > 0 {
		return &b[0]
	}
	return nil
}
