package cbc

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"log"
)

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	// Buffer the size of one block used in CryptBlocks
	blockBuff []byte
}

type cbcEncrypter cbc

// NewEncrypter returns a BlockMode which encrypts using CBC.
// Returns an error if the iv is not long enough.
func NewEncrypter(b cipher.Block, iv []byte) (cipher.BlockMode, error) {
	if iv == nil || len(iv) < b.BlockSize() {
		return nil, errors.New("cipher/modes: IV needs to be exactly one block")
	}

	// TODO check if successful
	blockBuff := make([]byte, b.BlockSize())

	return &cbcEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		blockBuff: blockBuff,
	}, nil
}

func (e *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		log.Panic("cipher/modes: input not full blocks")
	}
	if len(dst) < len(src) {
		log.Panic("cipher/modes: dst not large enough")
	}

	if len(src) == 0 {
		return
	}

	blockSize := e.blockSize
	nbrBlocks := len(src) / blockSize

	// First block
	subtle.XORBytes(e.blockBuff, e.iv, src[:blockSize])
	e.b.Encrypt(dst[:blockSize], e.blockBuff)

	// Compute E(pt[i] xor ct[i-1])
	for blockI := 1; blockI < nbrBlocks; blockI++ {
		subtle.XORBytes(e.blockBuff, dst[(blockI-1)*blockSize:blockI*blockSize], src[blockI*blockSize:(blockI+1)*blockSize])
		e.b.Encrypt(dst[blockI*blockSize:(blockI+1)*blockSize], e.blockBuff)
	}
}

func (e *cbcEncrypter) BlockSize() int {
	return e.blockSize
}


type cbcDecrypter cbc

// NewDecrypter returns a BlockMode which decrypts using CBC.
// Returns an error if the iv is not long enough.
func NewDecrypter(b cipher.Block, iv []byte) (cipher.BlockMode, error) {
	if iv == nil || len(iv) != b.BlockSize() {
		return nil, errors.New("cipher/modes: IV needs to be exactly one block")
	}

	// TODO check if successful
	blockBuff := make([]byte, b.BlockSize())

	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		blockBuff: blockBuff,
	}, nil
}

func (e *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		log.Panic("cipher/modes: input not full blocks")
	}
	if len(dst) < len(src) {
		log.Panic("cipher/modes: dst not large enough")
	}

	if len(src) == 0 {
		return
	}

	blockSize := e.blockSize
	nbrBlocks := len(src) / blockSize

	// First block
	e.b.Decrypt(e.blockBuff, src[:blockSize])
	subtle.XORBytes(dst[:blockSize], e.iv, e.blockBuff)

	// Compute E(pt[i] xor ct[i-1])
	for blockI := 1; blockI < nbrBlocks; blockI++ {
		e.b.Decrypt(e.blockBuff, src[blockI*blockSize:(blockI+1)*blockSize])
		subtle.XORBytes(dst[blockI*blockSize:(blockI+1)*blockSize], e.blockBuff, src[(blockI-1)*blockSize:blockI*blockSize])
	}
}

func (e *cbcDecrypter) BlockSize() int {
	return e.blockSize
}