package sha256

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	lh "github.com/loicbacciga/crypto-go/src/hash"
)

type hType int

const (
	h224 hType = iota
	h256
)

type digest struct {
	buf                            []byte
	h0, h1, h2, h3, h4, h5, h6, h7 uint32
	wt                             [64]uint32
	writenBits                     big.Int
	htype                          hType
}

const BlockSize int = 512 / 8
const Size256 int = 256 / 8
const Size224 int = 224 / 8

func rotr(x uint32, n int) uint32 {
	return (x >> n) | (x << (32 - n))
}

func shr(x uint32, n int) uint32 {
	return x >> n
}

func sigmBig0(x uint32) uint32 {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

func sigmBig1(x uint32) uint32 {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

func sigmSmall0(x uint32) uint32 {
	return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

func sigmSmall1(x uint32) uint32 {
	return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// Constants
var k = [...]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// FUNCTIONS

func Sum224(data []byte) [Size224]byte {
	h := New224()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size224]byte)(res[:])
}

func Sum256(data []byte) [Size256]byte {
	h := New256()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size256]byte)(res[:])
}

// HASH
func New224() hash.Hash {
	d := new(digest)
	d.htype = h224
	d.Reset()
	return d
}

func New256() hash.Hash {
	d := new(digest)
	d.htype = h256
	d.Reset()
	return d
}

func (dig *digest) Write(p []byte) (n int, err error) {
	toBeAdded := big.NewInt(0).Add(big.NewInt(int64(len(p))), big.NewInt(int64(len(dig.buf))))

	if big.NewInt(0).Add(&dig.writenBits, toBeAdded).BitLen() > 64 {
		return 0, errors.New("not enough room left")
	}

	// Just append to the already written data
	dig.buf = append(dig.buf, p...)

	// Wait until there are enough blocks
	for len(dig.buf) >= BlockSize {
		Mi := dig.buf[:BlockSize]

		// Prepare schedule
		for t := range dig.wt {
			if t <= 15 {
				dig.wt[t] = binary.BigEndian.Uint32(Mi[4*t : 4*(t+1)])
			} else {
				dig.wt[t] = sigmSmall1(dig.wt[t-2]) + dig.wt[t-7] + sigmSmall0(dig.wt[t-15]) + dig.wt[t-16]
			}
		}

		// Init working variables
		a, b, c, d, e, f, g, h := dig.h0, dig.h1, dig.h2, dig.h3, dig.h4, dig.h5, dig.h6, dig.h7

		for t := range dig.wt {
			T1 := h + sigmBig1(e) + ch(e, f, g) + k[t] + dig.wt[t]
			T2 := sigmBig0(a) + maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + T1
			d = c
			c = b
			b = a
			a = T1 + T2
		}

		// Compute wt
		dig.h0 = a + dig.h0
		dig.h1 = b + dig.h1
		dig.h2 = c + dig.h2
		dig.h3 = d + dig.h3
		dig.h4 = e + dig.h4
		dig.h5 = f + dig.h5
		dig.h6 = g + dig.h6
		dig.h7 = h + dig.h7

		dig.buf = dig.buf[BlockSize:]
		dig.writenBits = *big.NewInt(0).Add(&dig.writenBits, big.NewInt(int64(BlockSize)*8))
	}

	return len(p), nil
}

func (d *digest) Sum(b []byte) []byte {
	l := big.NewInt(0).Add(&d.writenBits, big.NewInt(int64(len(d.buf))*8))
	pad := lh.ShaPadding32(l)
	d.Write(pad)

	res := make([]byte, Size256)
	binary.BigEndian.PutUint32(res, d.h0)
	binary.BigEndian.PutUint32(res[4:], d.h1)
	binary.BigEndian.PutUint32(res[8:], d.h2)
	binary.BigEndian.PutUint32(res[12:], d.h3)
	binary.BigEndian.PutUint32(res[16:], d.h4)
	binary.BigEndian.PutUint32(res[20:], d.h5)
	binary.BigEndian.PutUint32(res[24:], d.h6)
	binary.BigEndian.PutUint32(res[28:], d.h7)

	return append(b, res[:d.Size()]...)
}

func (d *digest) Reset() {
	d.buf = make([]byte, 0)
	d.writenBits = *big.NewInt(0)

	if d.htype == h224 {
		d.h0 = 0xc1059ed8
		d.h1 = 0x367cd507
		d.h2 = 0x3070dd17
		d.h3 = 0xf70e5939
		d.h4 = 0xffc00b31
		d.h5 = 0x68581511
		d.h6 = 0x64f98fa7
		d.h7 = 0xbefa4fa4
	} else {
		d.h0 = 0x6a09e667
		d.h1 = 0xbb67ae85
		d.h2 = 0x3c6ef372
		d.h3 = 0xa54ff53a
		d.h4 = 0x510e527f
		d.h5 = 0x9b05688c
		d.h6 = 0x1f83d9ab
		d.h7 = 0x5be0cd19
	}
}

func (d *digest) Size() int {
	if d.htype == h224 {
		return Size224
	} else {
		return Size256
	}
}

func (d *digest) BlockSize() int {
	return BlockSize
}
