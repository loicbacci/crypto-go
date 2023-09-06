package chacha20

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"log"
	"math/bits"
)

// RFC 7539

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	// 1.
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)

	// 2.
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)

	// 3.
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)

	// 4.
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)

	return a, b, c, d
}

type chacha20 struct {
	key        []byte
	nonce      []byte
	blockCount uint32
}

type stateType = [16]uint32

// New creates a new TLS ChaCha20 cipher, as defined in RFC7539.
// key is 256-bits (eight 32-bits integers)
// nonce is 96-bits (three 32-bits integers)
// blockCount is by default 1 (use NewWithBlockCount to change this value)
func New(key, nonce []byte) (cipher.Stream, error) {
	return NewWithBlockCount(key, nonce, 1)
}

// NewWithBlockCount creates a new TLS ChaCha20 cipher with the given blockCount value, as defined in RFC7539.
// key is 256-bits (eight 32-bits integers)
// nonce is 96-bits (three 32-bits integers)
// blockCount is a 32-bit integer
func NewWithBlockCount(key, nonce []byte, blockCount uint32) (cipher.Stream, error) {
	if len(key) != 256/8 {
		return nil, errors.New("key too short")
	}
	if len(nonce) != 96/8 {
		return nil, errors.New("nonce too short")
	}

	return &chacha20{
		key:        key,
		nonce:      nonce,
		blockCount: blockCount,
	}, nil
}

// getInitState creates the initial state of the block function
// blockCount is passed as a parameter
func (ch *chacha20) getInitState(blockCount uint32) stateType {
	return stateType{
		// Constants (4 words 0-3)
		0x61707865,
		0x3320646e,
		0x79622d32,
		0x6b206574,
		// Key (8 words 4-11)
		binary.LittleEndian.Uint32(ch.key[0:4]),
		binary.LittleEndian.Uint32(ch.key[4:8]),
		binary.LittleEndian.Uint32(ch.key[8:12]),
		binary.LittleEndian.Uint32(ch.key[12:16]),
		binary.LittleEndian.Uint32(ch.key[16:20]),
		binary.LittleEndian.Uint32(ch.key[20:24]),
		binary.LittleEndian.Uint32(ch.key[24:28]),
		binary.LittleEndian.Uint32(ch.key[28:32]),
		// Block counter (1 word 12)
		blockCount,
		// Nonce (2 words 13-15)
		binary.LittleEndian.Uint32(ch.nonce[0:4]),
		binary.LittleEndian.Uint32(ch.nonce[4:8]),
		binary.LittleEndian.Uint32(ch.nonce[8:12]),
	}
}

// applyQuarterRound applies a quarterRound on the internal state to the given entries
func applyQuarterRound(state *stateType, i1, i2, i3, i4 int) {
	a, b, c, d := quarterRound(state[i1], state[i2], state[i3], state[i4])
	state[i1] = a
	state[i2] = b
	state[i3] = c
	state[i4] = d
}

// blockFn is the ChaCha20 block function
func (ch *chacha20) blockFn(blockCount uint32) []byte {
	initState := ch.getInitState(blockCount)
	state := initState

	// Run 20 rounds of 4 quarter rounds
	for ri := 0; ri < 10; ri++ {
		applyQuarterRound(&state, 0, 4, 8, 12)
		applyQuarterRound(&state, 1, 5, 9, 13)
		applyQuarterRound(&state, 2, 6, 10, 14)
		applyQuarterRound(&state, 3, 7, 11, 15)
		applyQuarterRound(&state, 0, 5, 10, 15)
		applyQuarterRound(&state, 1, 6, 11, 12)
		applyQuarterRound(&state, 2, 7, 8, 13)
		applyQuarterRound(&state, 3, 4, 9, 14)
	}

	// Create output by adding the initState and state
	resBytes := make([]byte, 16*4)
	for i := range initState {
		binary.LittleEndian.PutUint32(resBytes[4*i:4*(i+1)], state[i]+initState[i])
	}

	return resBytes
}

func (ch *chacha20) BlockSize() int {
	return 64
}

func (ch *chacha20) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		log.Panic("cipher: dst is too small")
	}

	// TODO account for multiple consecutive calls to this function

	// TODO check for overflow
	blockSize := ch.BlockSize()
	nbrBlocks := len(src) / blockSize
	nbrRestBytes := len(src) - (nbrBlocks * blockSize)

	// Encrypt the full blocks
	for blockI := 0; blockI < nbrBlocks; blockI++ {
		keyBlock := ch.blockFn(ch.blockCount + uint32(blockI))
		// dst = src xor key
		subtle.XORBytes(dst[blockSize*blockI:blockSize*(blockI+1)], src[blockSize*blockI:blockSize*(blockI+1)], keyBlock)
	}

	// Encrypt last bytes
	if nbrRestBytes != 0 {
		keyBlock := ch.blockFn(ch.blockCount + uint32(nbrBlocks))
		// dst = src xor key
		subtle.XORBytes(dst[blockSize*nbrBlocks:], src[blockSize*nbrBlocks:], keyBlock[:nbrRestBytes])
	}
}
