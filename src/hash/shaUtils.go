package hash

import (
	"encoding/binary"
)

// Padding

func ShaPadding32(l uint64) []byte {
	res := make([]byte, 0)

	// l is length of the message in bits
	k := (448 - 1 - l) % 512

	// append "1" + "0"*k + l (in 64 bits)

	// append first byte
	padF := byte(1 << 7)
	res = append(res, padF)

	k -= 7

	// append rest of zeros
	for k > 0 {
		res = append(res, byte(0))
		k -= 8
	}

	// append l
	lBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lBytes, uint64(l))
	res = append(res, lBytes...)

	return res
}

func ShaPadding64(buf *[]byte) error {
	// l is length of the message in bits
	lenBytes := len(*buf)

	k := (896 - 1 - (lenBytes%1024)*8) % 1024

	// append "1" + "0"*k + l (in 64 bits)

	// append first byte
	padF := byte(1 << 7)
	*buf = append(*buf, padF)

	k -= 7

	// append rest of zeros
	for k > 0 {
		*buf = append(*buf, byte(0))
		k -= 8
	}

	// append l
	lBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(lBytes, uint64(lenBytes))
	*buf = append(*buf, lBytes...)
	return nil
}

// Functions

func Rotr32(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

func Shr32(x uint32, n int) uint32 {
	return x >> n
}

func SigmBig032(x uint32) uint32 {
	return Rotr32(x, 2) ^ Rotr32(x, 13) ^ Rotr32(x, 22)
}

func SigmBig132(x uint32) uint32 {
	return Rotr32(x, 6) ^ Rotr32(x, 11) ^ Rotr32(x, 25)
}

func SigmSmall032(x uint32) uint32 {
	return Rotr32(x, 7) ^ Rotr32(x, 18) ^ Shr32(x, 3)
}

func SigmSmall132(x uint32) uint32 {
	return Rotr32(x, 17) ^ Rotr32(x, 19) ^ Shr32(x, 10)
}

func Ch32(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func Maj32(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// Constants
var K32 = [...]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
