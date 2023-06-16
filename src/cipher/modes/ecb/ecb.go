package ecb

import (
	"crypto/cipher"
	"log"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb

// NewEncrypter returns a BlockMode which encrypts using ECB
func NewEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		log.Panic("cipher/modes: input not full blocks")
	}
	if len(dst) < len(src) {
		log.Panic("cipher/modes: dst not large enough")
	}

	blockSize := e.blockSize

	for blockStart := 0; blockStart < len(src); blockStart += e.blockSize {
		e.b.Encrypt(dst[blockStart:blockStart+blockSize], src[blockStart:blockStart+blockSize])
	}
}

func (e *ecbEncrypter) BlockSize() int {
	return e.blockSize
}

type ecbDecrypter ecb

// NewDecrypter returns a BlockMode which decrypts using ECB
func NewDecrypter(b cipher.Block) cipher.BlockMode {
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
