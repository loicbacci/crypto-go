package utils

import "crypto/cipher"

type dummyBlock struct{
	blockSize int
}

func (d *dummyBlock) BlockSize() int {
	return d.blockSize
}
func (d *dummyBlock) Encrypt(dst, src []byte) {
	copy(dst, src)
}
func (d *dummyBlock) Decrypt(dst, src []byte) {
	copy(dst, src)
}

func NewDummyCipher(blockSize int) cipher.Block {
	return &dummyBlock{blockSize: blockSize}
}
