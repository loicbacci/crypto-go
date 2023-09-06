package cbc

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/loicbacciga/crypto-go/src/cipher/utils"
	"github.com/loicbacciga/crypto-go/src/cipher/des"
)

func TestCBCEncrypt(t *testing.T) {
	// size of uint16
	blockSize := 2

	blockCipher := utils.NewDummyCipher(blockSize)
	// iv = 0x01
	iv := make([]byte, 0)
	iv = binary.BigEndian.AppendUint16(iv, 1)

	encrypter, err := NewEncrypter(blockCipher, iv)
	if err != nil {
		t.Fatal(err.Error())
	}

	// src = 0x0203
	src := make([]byte, 0)
	src = binary.BigEndian.AppendUint16(src, 2)
	src = binary.BigEndian.AppendUint16(src, 3)

	// exp = 0x(01^02)|(01^02^03)
	exp := make([]byte, 0)
	exp = binary.BigEndian.AppendUint16(exp, 1 ^ 2)
	exp = binary.BigEndian.AppendUint16(exp, 1 ^ 2 ^ 3)

	// res
	dst := make([]byte, 2*blockSize)
	encrypter.CryptBlocks(dst, src)

	if !reflect.DeepEqual(dst, exp) {
		t.Errorf(hex.EncodeToString(exp) + " != " + hex.EncodeToString(dst))
	}
}

func TestCBCDecrypt(t *testing.T) {
	// size of uint16
	blockSize := 2

	blockCipher := utils.NewDummyCipher(blockSize)
	// iv = 0x01
	iv := make([]byte, 0)
	iv = binary.BigEndian.AppendUint16(iv, 1)

	decrypter, err := NewDecrypter(blockCipher, iv)
	if err != nil {
		t.Fatal(err.Error())
	}

	// ctxt = 0x0203
	ctxt := make([]byte, 0)
	ctxt = binary.BigEndian.AppendUint16(ctxt, 2)
	ctxt = binary.BigEndian.AppendUint16(ctxt, 3)

	// exp = 0x(01^02)|(02^03)
	exp := make([]byte, 0)
	exp = binary.BigEndian.AppendUint16(exp, 1 ^ 2)
	exp = binary.BigEndian.AppendUint16(exp, 2 ^ 3)

	// res
	ptxt := make([]byte, 2*blockSize)
	decrypter.CryptBlocks(ptxt, ctxt)

	if !reflect.DeepEqual(ptxt, exp) {
		t.Errorf("%s != %s", hex.EncodeToString(exp), hex.EncodeToString(ptxt))
	}
}

func TestCBC(t *testing.T) {
	key := make([]byte, 0)
	key = binary.BigEndian.AppendUint64(key, 123)
	
	blockCipher := des.New(key)

	// ptxt
	ptxt := make([]byte, 0)
	ptxt = binary.BigEndian.AppendUint64(ptxt, 1)
	ptxt = binary.BigEndian.AppendUint64(ptxt, 2)
	ptxt = binary.BigEndian.AppendUint64(ptxt, 3)

	// iv
	iv := make([]byte, 0)
	iv = binary.BigEndian.AppendUint64(iv, 8)

	encrypter, err := NewEncrypter(blockCipher, iv)
	if err != nil {
		t.Fatal(err.Error())
	}

	decrypter, err := NewDecrypter(blockCipher, iv)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Encrypt
	ctxt := make([]byte, len(ptxt))
	encrypter.CryptBlocks(ctxt, ptxt)

	// Decrypt
	res := make([]byte, len(ctxt))
	decrypter.CryptBlocks(res, ctxt)

	if !reflect.DeepEqual(ptxt, res) {
		t.Errorf("%s != %s", hex.EncodeToString(res), hex.EncodeToString(ptxt))
	}
}
