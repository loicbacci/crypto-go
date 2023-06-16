package sha256

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestABC256(t *testing.T) {
	msg := []byte("abc")

	res := Sum256(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha256.Sum256(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestABC224(t *testing.T) {
	msg := []byte("abc")

	res := Sum224(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha256.Sum224(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom256(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum256(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha256.Sum256(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}

func TestRandom224(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum224(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha256.Sum224(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}
