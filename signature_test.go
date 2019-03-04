package ncryptf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestV1Signature(t *testing.T) {
	instance := NewInstance(t)

	for index, test := range instance.testCases {
		signature := Derive(test.method, test.uri, instance.salt, instance.date, test.payload, 1)

		lines := strings.Split(signature, "\n")
		assert.Equal(t, instance.v1SignatureResults[index], lines[0], "v1 signature matches")
	}
}

func TestV2Signature(t *testing.T) {
	instance := NewInstance(t)

	for index, test := range instance.testCases {
		signature := Derive(test.method, test.uri, instance.salt, instance.date, test.payload, 2)

		fmt.Printf("Signature: %s\n", signature)
		lines := strings.Split(signature, "\n")
		assert.Equal(t, instance.v2SignatureResults[index], lines[0], "v2 signature matches")
	}
}
