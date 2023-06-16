package sha256

import (
	"encoding/binary"
	"errors"
	"hash"
	"math"

	lh "github.com/loicbacciga/crypto-go/src/hash"
)

type HType int

const (
	H224 HType = iota
	H256
)

type digest struct {
	buf                            []byte
	h0, h1, h2, h3, h4, h5, h6, h7 uint32
	wt                             [64]uint32
	writenBits                     uint64
	htype                          HType
}

const BlockSize int = 512 / 8
const Size256 int = 256 / 8
const Size224 int = 224 / 8

// Word size in bits
const wordSize int = 32

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
	d.htype = H224
	d.Reset()
	return d
}

func New256() hash.Hash {
	d := new(digest)
	d.htype = H256
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
					dig.wt[t] = lh.SigmSmall132(dig.wt[t-2]) + dig.wt[t-7] + lh.SigmSmall032(dig.wt[t-15]) + dig.wt[t-16]
				}
			}

			// Init working variables
			a, b, c, d, e, f, g, h := dig.h0, dig.h1, dig.h2, dig.h3, dig.h4, dig.h5, dig.h6, dig.h7

			for t := range dig.wt {
				T1 := h + lh.SigmBig132(e) + lh.Ch32(e, f, g) + lh.K32[t] + dig.wt[t]
				T2 := lh.SigmBig032(a) + lh.Maj32(a, b, c)
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
	pad := lh.ShaPadding32(l)
	d.Write(pad)

	s := 0
	if d.htype == H224 {
		s = Size224
	} else {
		s = Size256
	}
	res := make([]byte, s)
	binary.BigEndian.PutUint32(res, d.h0)
	binary.BigEndian.PutUint32(res[4:], d.h1)
	binary.BigEndian.PutUint32(res[8:], d.h2)
	binary.BigEndian.PutUint32(res[12:], d.h3)
	binary.BigEndian.PutUint32(res[16:], d.h4)
	binary.BigEndian.PutUint32(res[20:], d.h5)
	binary.BigEndian.PutUint32(res[24:], d.h6)
	if d.htype == H256 {
		binary.BigEndian.PutUint32(res[28:], d.h7)
	}

	return append(b, res[:]...)
}

func (d *digest) Reset() {
	d.buf = make([]byte, 0)

	if d.htype == H224 {
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
	if d.htype == H224 {
		return Size224
	} else {
		return Size256
	}
}

func (d *digest) BlockSize() int {
	return BlockSize
}
