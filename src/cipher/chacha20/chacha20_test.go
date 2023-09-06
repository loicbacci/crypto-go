// Package chacha20 implements the ChaCha20 stream cipher, as modified for TLS.
// c.f. RFC7539 https://datatracker.ietf.org/doc/html/rfc7539
package chacha20

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestQuarterRound(t *testing.T) {
	// Inputs
	a := uint32(0x11111111)
	b := uint32(0x01020304)
	c := uint32(0x9b8d6f43)
	d := uint32(0x01234567)

	// Expected
	expA := uint32(0xea2a92f4)
	expB := uint32(0xcb1cf8ce)
	expC := uint32(0x4581472e)
	expD := uint32(0x5881c4bb)

	// Check
	resA, resB, resC, resD := quarterRound(a, b, c, d)

	if expA != resA {
		t.Errorf("A: %d != %d (exp != res)", expA, resA)
	}

	if expB != resB {
		t.Errorf("B: %d != %d (exp != res)", expB, resB)
	}

	if expC != resC {
		t.Errorf("C: %d != %d (exp != res)", expC, resC)
	}

	if expD != resD {
		t.Errorf("D: %d != %d (exp != res)", expD, resD)
	}
}

func TestBlockFn(t *testing.T) {
	key := make([]byte, 0)
	key = binary.BigEndian.AppendUint32(key, 0x00010203)
	key = binary.BigEndian.AppendUint32(key, 0x04050607)
	key = binary.BigEndian.AppendUint32(key, 0x08090a0b)
	key = binary.BigEndian.AppendUint32(key, 0x0c0d0e0f)
	key = binary.BigEndian.AppendUint32(key, 0x10111213)
	key = binary.BigEndian.AppendUint32(key, 0x14151617)
	key = binary.BigEndian.AppendUint32(key, 0x18191a1b)
	key = binary.BigEndian.AppendUint32(key, 0x1c1d1e1f)

	nonce := make([]byte, 0)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000009)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x0000004a)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000000)

	ch := &chacha20{key: key, nonce: nonce, blockCount: 1}

	res := ch.blockFn(1)

	exp := [16]uint32{
		0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
		0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
		0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
		0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
	}
	expBytes := make([]byte, 0)
	for _, v := range exp {
		expBytes = binary.LittleEndian.AppendUint32(expBytes, v)
	}

	if !reflect.DeepEqual(res, expBytes) {
		t.Errorf("%s != %s (exp != res)", hex.EncodeToString(expBytes), hex.EncodeToString(res))
	}
}

func TestEncrypt(t *testing.T) {
	key := make([]byte, 0)
	key = binary.BigEndian.AppendUint32(key, 0x00010203)
	key = binary.BigEndian.AppendUint32(key, 0x04050607)
	key = binary.BigEndian.AppendUint32(key, 0x08090a0b)
	key = binary.BigEndian.AppendUint32(key, 0x0c0d0e0f)
	key = binary.BigEndian.AppendUint32(key, 0x10111213)
	key = binary.BigEndian.AppendUint32(key, 0x14151617)
	key = binary.BigEndian.AppendUint32(key, 0x18191a1b)
	key = binary.BigEndian.AppendUint32(key, 0x1c1d1e1f)

	nonce := make([]byte, 0)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000000)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x0000004a)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000000)

	ch, err := New(key, nonce)
	if err != nil {
		t.Fatal(err.Error())
	}

	ptxt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	res := make([]byte, len(ptxt))

	ch.XORKeyStream(res, ptxt)

	expStr := "6e2e359a2568f98041ba0728dd0d6981" +
		"e97e7aec1d4360c20a27afccfd9fae0b" +
		"f91b65c5524733ab8f593dabcd62b357" +
		"1639d624e65152ab8f530c359f0861d8" +
		"07ca0dbf500d6a6156a38e088a22b65e" +
		"52bc514d16ccf806818ce91ab7793736" +
		"5af90bbf74a35be6b40b8eedf2785e42" +
		"874d"

	expB, _ := hex.DecodeString(expStr)

	if !reflect.DeepEqual(expB, res) {
		t.Errorf("%s != %s (exp != res)", hex.EncodeToString(expB), hex.EncodeToString(res))
	}
}

func TestDecrypt(t *testing.T) {
	key := make([]byte, 0)
	key = binary.BigEndian.AppendUint32(key, 0x00010203)
	key = binary.BigEndian.AppendUint32(key, 0x04050607)
	key = binary.BigEndian.AppendUint32(key, 0x08090a0b)
	key = binary.BigEndian.AppendUint32(key, 0x0c0d0e0f)
	key = binary.BigEndian.AppendUint32(key, 0x10111213)
	key = binary.BigEndian.AppendUint32(key, 0x14151617)
	key = binary.BigEndian.AppendUint32(key, 0x18191a1b)
	key = binary.BigEndian.AppendUint32(key, 0x1c1d1e1f)

	nonce := make([]byte, 0)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000000)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x0000004a)
	nonce = binary.BigEndian.AppendUint32(nonce, 0x00000000)

	ch, err := New(key, nonce)
	if err != nil {
		t.Fatal(err.Error())
	}

	ctxtStr := "6e2e359a2568f98041ba0728dd0d6981" +
		"e97e7aec1d4360c20a27afccfd9fae0b" +
		"f91b65c5524733ab8f593dabcd62b357" +
		"1639d624e65152ab8f530c359f0861d8" +
		"07ca0dbf500d6a6156a38e088a22b65e" +
		"52bc514d16ccf806818ce91ab7793736" +
		"5af90bbf74a35be6b40b8eedf2785e42" +
		"874d"

	ctxt, _ := hex.DecodeString(ctxtStr)

	exp := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	res := make([]byte, len(ctxt))

	ch.XORKeyStream(res, ctxt)

	if !reflect.DeepEqual(exp, res) {
		t.Errorf("%s != %s (exp != res)", hex.EncodeToString(exp), hex.EncodeToString(res))
	}
}
