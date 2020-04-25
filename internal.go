package ncryptf

import (
	"io"

	"github.com/jamesruan/sodium"
)

type randomBytes struct {
	sodium.Bytes
}

func (k randomBytes) Size() int {
	return 32
}

type jsonAuthorization struct {
	AccessToken string `json:"access_token"`
	Date        string `json:"date"`
	Hmac        string `json:"hmac"`
	Salt        string `json:"salt"`
	Version     int    `json:"v"`
}

func bytePointer(b []byte) *uint8 {
	if len(b) > 0 {
		return &b[0]
	}
	return nil
}

// Helper function to get first 32 bytes of HMAC
func streamToBytes(stream io.Reader) []byte {
	out := make([]byte, 32)

	n, err := io.ReadFull(stream, out)
	if n != 32 || err != nil {
		return nil
	}

	return out
}
