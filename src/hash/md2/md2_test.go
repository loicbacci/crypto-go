package md2

import (
	"encoding/hex"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	msg := []byte("Hello world")
	expHex := "195d5b5475ec3e6760f888511f20b84d"

	res := Sum(msg)
	resHex := hex.EncodeToString(res[:])

	if resHex != expHex {
		t.Errorf("Not equal %s!=%s", resHex, expHex)
	}
}

func TestQuickBrownFox(t *testing.T) {
	msg := []byte("The quick brown fox jumps over the lazy dog")
	expHex := "03d85a0d629d2c442e987525319fc471"

	res := Sum(msg)
	resHex := hex.EncodeToString(res[:])

	if resHex != expHex {
		t.Errorf("Not equal %s != %s", resHex, expHex)
	}
}

func TestEmpty(t *testing.T) {
	msg := []byte("")
	expHex := "8350e5a3e24c153df2275c9f80692773"

	res := Sum(msg)
	resHex := hex.EncodeToString(res[:])

	if resHex != expHex {
		t.Errorf("Not equal %s != %s", resHex, expHex)
	}
}

func TestRFC(t *testing.T) {
	msgs := []string{
		"",
		"a",
		"abc",
		"message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	}

	expHexs := []string{
		"8350e5a3e24c153df2275c9f80692773",
		"32ec01ec4a6dac72c0ab96fb34c0b5d1",
		"da853b0d3f88d99b30283a69e6ded6bb",
		"ab4f496bfb2a530b219ff33031fe06b0",
		"4e8ddff3650292ab5a4108c3aa47940b",
		"da33def2a42df13975352846c30338cd",
		"d5976f79d83d3a0dc9806c3c66f3efd8",
	}

	for i := range msgs {
		msg := []byte(msgs[i])
		expHex := expHexs[i]

		res := Sum(msg)
		resHex := hex.EncodeToString(res[:])

		if resHex != expHex {
			t.Errorf("MD2(%s) %s != %s", msgs[i], resHex, expHex)
		}
	}
}
