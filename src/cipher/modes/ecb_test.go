package modes

import (
	"crypto/rand"
	"testing"
)

const blockSize int = 16

type dummyBlock struct{}

func (d *dummyBlock) BlockSize() int {
	return blockSize
}
func (d *dummyBlock) Encrypt(dst, src []byte) {
	for i := range src {
		dst[i] = src[i] ^ 0xff
	}
}
func (d *dummyBlock) Decrypt(dst, src []byte) {
	for i := range src {
		dst[i] = src[i] ^ 0xff
	}
}

func TestECB(t *testing.T) {
	ecbEnc := NewECBEncrypter(&dummyBlock{})

	nbrBlocks := 10
	src := make([]byte, blockSize*nbrBlocks)

	_, err := rand.Read(src)
	if err != nil {
		t.Fatal("Failed to generate random src")
	}

	encrypted := make([]byte, len(src))
	for i := range encrypted {
		encrypted[i] = 0x00
	}

	// Encrypt
	ecbEnc.CryptBlocks(encrypted, src)

	// Check result
	for i := range encrypted {
		if encrypted[i] != src[i]^0xff {
			t.Error()
		}
	}

	// Decrypt
	decrypted := make([]byte, len(src))

	ecbDec := NewECBDecrypter(&dummyBlock{})
	ecbDec.CryptBlocks(decrypted, encrypted)

	// Check result
	for i := range decrypted {
		if decrypted[i] != src[i] {
			t.Error()
		}
	}
}
