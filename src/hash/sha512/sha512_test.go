package sha512

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestABC512(t *testing.T) {
	msg := []byte("abc")

	res := Sum512(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha512.Sum512(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom512(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum512(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha512.Sum512(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}

func TestABC384(t *testing.T) {
	msg := []byte("abc")

	res := Sum384(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha512.Sum384(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom384(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum384(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha512.Sum384(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}

func TestABC512_224(t *testing.T) {
	msg := []byte("abc")

	res := Sum512_224(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha512.Sum512_224(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom512_224(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum512_224(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha512.Sum512_224(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}

func TestABC512_256(t *testing.T) {
	msg := []byte("abc")

	res := Sum512_256(msg)
	resHex := hex.EncodeToString(res[:])

	exp := sha512.Sum512_256(msg)
	expHex := hex.EncodeToString(exp[:])

	if expHex != resHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestRandom512_256(t *testing.T) {
	tries := 1000

	for tr := 0; tr < tries; tr++ {
		msgBitLen := rand.Intn(100)
		msg := make([]byte, msgBitLen/8+1)
		crand.Read(msg)

		res := Sum512_256(msg)
		resHex := hex.EncodeToString(res[:])

		exp := sha512.Sum512_256(msg)
		expHex := hex.EncodeToString(exp[:])

		if expHex != resHex {
			t.Errorf("Not equal %s!=%s", resHex, expHex)
		}
	}
}
