package ncryptf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unsafe"
)

// Derive derives the signature for a given version
func Derive(httpMethod string, uri string, salt []byte, date time.Time, payload string, version int) string {

	hash := getSignatureHash(payload, salt, version)
	b64Salt := base64.StdEncoding.EncodeToString(salt)
	timestamp := date.UTC().Format(time.RFC1123Z)

	return hash + "\n" +
		httpMethod + "+" + uri + "\n" +
		timestamp + "\n" +
		b64Salt
}

func getSignatureHash(data string, salt []byte, version int) string {
	if version == 2 {
		hash := make([]byte, 64)
		dataBytes := []byte(data)
		db := bytePointer(dataBytes)

		C.crypto_generichash(
			(*C.uchar)(unsafe.Pointer(&hash[0])),
			C.size_t(len(hash)),
			(*C.uchar)(unsafe.Pointer(db)),
			C.ulonglong(len(dataBytes)),
			(*C.uchar)(unsafe.Pointer(&salt[0])),
			C.size_t(len(salt)))

		return base64.StdEncoding.EncodeToString(hash)
	}

	hash := sha256.New()
	hash.Write([]byte(data))
	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
}
