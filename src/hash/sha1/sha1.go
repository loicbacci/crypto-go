package sha1

import (
	"encoding/binary"
	"errors"
	"hash"
	"math"

	lbhash "github.com/loicbacciga/crypto-go/src/hash"
)

type digest struct {
	buf                []byte
	h0, h1, h2, h3, h4 uint32
	wt                 [80]uint32
	writenBits         uint64
}

const BlockSize int = 512 / 8
const Size int = 160 / 8

// Word size in bits
const wordSize int = 32

// FUNCTIONS

// rotate left
func rotl(x uint32, n int) uint32 {
	return (x << n) | (x >> (wordSize - n))
}

func ft(t int, x, y, z uint32) uint32 {
	if 0 <= t && t <= 19 {
		// Ch
		return (x & y) ^ (^x & z)
	} else if 20 <= t && t <= 39 {
		// Parity
		return x ^ y ^ z
	} else if 40 <= t && t <= 59 {
		// Maj
		return (x & y) ^ (x & z) ^ (y & z)
	} else {
		// Parity
		return x ^ y ^ z
	}
}

func kt(t int) uint32 {
	if 0 <= t && t <= 19 {
		return 0x5a827999
	} else if 20 <= t && t <= 39 {
		return 0x6ed9eba1
	} else if 40 <= t && t <= 59 {
		return 0x8f1bbcdc
	} else {
		return 0xca62c1d6
	}
}

// HASH

func Sum(data []byte) [Size]byte {
	h := New()
	h.Write(data)
	res := h.Sum(nil)

	return ([Size]byte)(res[:])
}

func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (dig *digest) Write(p []byte) (n int, err error) {
	// Just append to the already written data
	dig.buf = append(dig.buf, p...)

	// Wait until there are enough blocks
	if len(dig.buf) >= BlockSize {
		N := len(dig.buf) / BlockSize

		for i := 0; i < N; i++ {
			Mi := dig.buf[BlockSize*i : BlockSize*(i+1)]

			// Prepare schedule
			for t := range dig.wt {
				if t <= 15 {
					dig.wt[t] = binary.BigEndian.Uint32(Mi[4*t : 4*(t+1)])
				} else {
					dig.wt[t] = rotl(dig.wt[t-3]^dig.wt[t-8]^dig.wt[t-14]^dig.wt[t-16], 1)
				}
			}

			// Init working variables
			a, b, c, d, e := dig.h0, dig.h1, dig.h2, dig.h3, dig.h4

			for t := 0; t < 80; t++ {
				var T uint32 = rotl(a, 5) + ft(t, b, c, d) + e + kt(t) + dig.wt[t]
				e = d
				d = c
				c = rotl(b, 30)
				b = a
				a = T
			}

			// Compute wt
			dig.h0 = a + dig.h0
			dig.h1 = b + dig.h1
			dig.h2 = c + dig.h2
			dig.h3 = d + dig.h3
			dig.h4 = e + dig.h4
		}

		// Update written bits
		rst := len(dig.buf) - (len(dig.buf) % BlockSize)
		written := len(dig.buf) - rst

		// Check if written too large
		if written >= math.MaxUint64/8 || written+(int(dig.writenBits)/8) >= math.MaxUint64/8 {
			return 0, errors.New("written too many bytes")
		}
		dig.writenBits += uint64(written) * 8

		dig.buf = dig.buf[:written]
	}

	return len(p), nil
}

func (d *digest) Sum(b []byte) []byte {
	l := d.writenBits + uint64(len(d.buf))*8
	pad := lbhash.ShaPadding32(l)
	d.Write(pad)

	res := make([]byte, Size)
	binary.BigEndian.PutUint32(res, d.h0)
	binary.BigEndian.PutUint32(res[4:], d.h1)
	binary.BigEndian.PutUint32(res[8:], d.h2)
	binary.BigEndian.PutUint32(res[12:], d.h3)
	binary.BigEndian.PutUint32(res[16:], d.h4)
	return append(b, res[:]...)
}

func (d *digest) Reset() {
	d.buf = make([]byte, 0)
	d.h0 = 0x67452301
	d.h1 = 0xefcdab89
	d.h2 = 0x98badcfe
	d.h3 = 0x10325476
	d.h4 = 0xc3d2e1f0
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}
