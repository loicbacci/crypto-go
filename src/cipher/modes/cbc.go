package modes

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"log"
)

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

type cbcEncrypter cbc

// NewCBCEncrypter returns a BlockMode which encrypts using CBC
func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
	}
}

func (e *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		log.Panic("cipher/modes: input not full blocks")
	}
	if len(dst) < len(src) {
		log.Panic("cipher/modes: dst not large enough")
	}

	blockSize := e.blockSize

	for blockStart := 0; blockStart < len(src); blockStart += e.blockSize {
		subtle.XORBytes(dst[blockStart : blockStart+blockSize], )

		block := src[blockStart : blockStart+blockSize]
		e.b.Encrypt(dst[blockStart:blockStart+blockSize], src[blockStart:blockStart+blockSize])
	}
}

func (e *ecbEncrypter) BlockSize() int {
	return e.blockSize
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts using ECB
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		log.Panic("cipher/modes: input not full blocks")
	}
	if len(dst) < len(src) {
		log.Panic("cipher/modes: dst not large enough")
	}

	blockSize := e.blockSize

	for blockStart := 0; blockStart < len(src); blockStart += e.blockSize {
		e.b.Decrypt(dst[blockStart:blockStart+blockSize], src[blockStart:blockStart+blockSize])
	}
}

func (e *ecbDecrypter) BlockSize() int {
	return e.blockSize
}
