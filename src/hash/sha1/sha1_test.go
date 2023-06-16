package sha1

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestABC(t *testing.T) {
	msg := []byte("abc")

	res := Sum(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha1.Sum(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha1.Sum(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}
