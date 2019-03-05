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
