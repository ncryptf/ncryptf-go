package ncryptf

import "github.com/jamesruan/sodium"

type randomBytes struct {
	sodium.Bytes
}

func (k randomBytes) Size() int {
	return 32
}

type jsonAuthorization struct {
	access_token, date, hmac, salt string
}
