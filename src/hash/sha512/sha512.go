package sha512

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
)

type hType int

const (
	h512 hType = iota
	h384
	h512_224
	h512_256
)

type digest struct {
	buf                            []byte
	h0, h1, h2, h3, h4, h5, h6, h7 uint64
	wt                             [80]uint64
	writenBits                     big.Int
	htype                          hType
}

const BlockSize int = 1024 / 8
const Size512 int = 512 / 8
const Size384 int = 384 / 8
const Size512_224 int = 224 / 8
const Size512_256 int = 256 / 8

// FUNCTIONS

var k = [...]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// rotate right
func rotr(x uint64, n int) uint64 {
	return (x >> n) | (x << (64 - n))
}

// right shift
func shr(x uint64, n int) uint64 {
	return x >> n
}

func ch(x, y, z uint64) uint64 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint64) uint64 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func sigmBig0(x uint64) uint64 {
	return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

func sigmBig1(x uint64) uint64 {
	return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

func sigmSmall0(x uint64) uint64 {
	return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7)
}

func sigmSmall1(x uint64) uint64 {
	return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6)
}

func Sum512(data []byte) [Size512]byte {
	h := New512()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size512]byte)(res[:])
}

func Sum384(data []byte) [Size384]byte {
	h := New384()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size384]byte)(res[:])
}

func Sum512_224(data []byte) [Size512_224]byte {
	h := New512_224()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size512_224]byte)(res[:])
}

func Sum512_256(data []byte) [Size512_256]byte {
	h := New512_256()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size512_256]byte)(res[:])
}

func padding(l *big.Int) []byte {
	res := make([]byte, 0)

	// l is length of the message in bits
	lk := big.NewInt(0).Mod(l, big.NewInt(1024))

	k := (896 - 1 - lk.Uint64()) % 1024

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
	lBytes := make([]byte, 128/8)
	l.FillBytes(lBytes)
	res = append(res, lBytes...)
	return res
}

// HASH

func New512() hash.Hash {
	d := new(digest)
	d.htype = h512
	d.Reset()
	return d
}

func New384() hash.Hash {
	d := new(digest)
	d.htype = h384
	d.Reset()
	return d
}

func New512_224() hash.Hash {
	d := new(digest)
	d.htype = h512_224
	d.Reset()
	return d
}

func New512_256() hash.Hash {
	d := new(digest)
	d.htype = h512_256
	d.Reset()
	return d
}

func (dig *digest) Write(p []byte) (n int, err error) {
	toBeAdded := big.NewInt(0).Add(big.NewInt(int64(len(p))), big.NewInt(int64(len(dig.buf))))

	if big.NewInt(0).Add(&dig.writenBits, toBeAdded).BitLen() > 128 {
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
				dig.wt[t] = binary.BigEndian.Uint64(Mi[8*t : 8*(t+1)])
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
	bufBitLen := big.NewInt(0).Mul(big.NewInt(int64(len(d.buf))), big.NewInt(8))
	l := big.NewInt(0).Add(&d.writenBits, bufBitLen)
	pad := padding(l)
	d.Write(pad)

	res := make([]byte, Size512)
	binary.BigEndian.PutUint64(res, d.h0)
	binary.BigEndian.PutUint64(res[8:], d.h1)
	binary.BigEndian.PutUint64(res[8*2:], d.h2)
	binary.BigEndian.PutUint64(res[8*3:], d.h3)
	binary.BigEndian.PutUint64(res[8*4:], d.h4)
	binary.BigEndian.PutUint64(res[8*5:], d.h5)
	binary.BigEndian.PutUint64(res[8*6:], d.h6)
	binary.BigEndian.PutUint64(res[8*7:], d.h7)

	return append(b, res[:d.Size()]...)
}

func (d *digest) Reset() {
	d.buf = make([]byte, 0)
	d.writenBits = *big.NewInt(0)

	if d.htype == h512 {
		d.h0 = 0x6a09e667f3bcc908
		d.h1 = 0xbb67ae8584caa73b
		d.h2 = 0x3c6ef372fe94f82b
		d.h3 = 0xa54ff53a5f1d36f1
		d.h4 = 0x510e527fade682d1
		d.h5 = 0x9b05688c2b3e6c1f
		d.h6 = 0x1f83d9abfb41bd6b
		d.h7 = 0x5be0cd19137e2179
	} else if d.htype == h384 {
		d.h0 = 0xcbbb9d5dc1059ed8
		d.h1 = 0x629a292a367cd507
		d.h2 = 0x9159015a3070dd17
		d.h3 = 0x152fecd8f70e5939
		d.h4 = 0x67332667ffc00b31
		d.h5 = 0x8eb44a8768581511
		d.h6 = 0xdb0c2e0d64f98fa7
		d.h7 = 0x47b5481dbefa4fa4
	} else if d.htype == h512_224 {
		d.h0 = 0x8C3D37C819544DA2
		d.h1 = 0x73E1996689DCD4D6
		d.h2 = 0x1DFAB7AE32FF9C82
		d.h3 = 0x679DD514582F9FCF
		d.h4 = 0x0F6D2B697BD44DA8
		d.h5 = 0x77E36F7304C48942
		d.h6 = 0x3F9D85A86A1D36C8
		d.h7 = 0x1112E6AD91D692A1
	} else if d.htype == h512_256 {
		d.h0 = 0x22312194FC2BF72C
		d.h1 = 0x9F555FA3C84C64C2
		d.h2 = 0x2393B86B6F53B151
		d.h3 = 0x963877195940EABD
		d.h4 = 0x96283EE2A88EFFE3
		d.h5 = 0xBE5E1E2553863992
		d.h6 = 0x2B0199FC2C85B8AA
		d.h7 = 0x0EB72DDC81C52CA2
	}
}

func (d *digest) Size() int {
	if d.htype == h512 {
		return Size512
	} else if d.htype == h384 {
		return Size384
	} else if d.htype == h512_224 {
		return Size512_224
	} else {
		return Size512_256
	}
}

func (d *digest) BlockSize() int {
	return BlockSize
}
