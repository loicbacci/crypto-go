package des

import (
	"crypto/cipher"
	"encoding/binary"
	"log"
)

// FIPS 46-3

const BlockSize int = 8

// Permutation table for first step.
var ip = [...]int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var ipInv = [...]int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

var s1 = [64]uint8{
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
}

var s2 = [64]uint8{
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
}

var s3 = [64]uint8{
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
}

var s4 = [64]uint8{
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
}

var s5 = [64]uint8{
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
}

var s6 = [64]uint8{
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
}
var s7 = [64]uint8{
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
}
var s8 = [64]uint8{
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
}

var sTables = [8][64]uint8{
	s1, s2, s3, s4, s5, s6, s7, s8,
}

var p = [...]int{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
}

// pc1C is the permutation applied to the key to get C0 in KS
var pc1 = [...]int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

// leftShifts indicates how many left shifts are needed for each
// iteration of KS
var leftShifts = [...]int{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
}

var pc2 = [...]int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var eTable = [...]int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

const Mask28 uint64 = 0b1111111111111111111111111111
const Mask64 uint64 = 0xffffffffffffffff
const Mask32 uint64 = 0xffffffff
const Mask56 = 0xffffffffffffff

type des struct {
	keys [16]uint64
}

// New creates a new DES cipher.
// key is 64 bits.
func New(key []byte) cipher.Block {
	keyU := binary.BigEndian.Uint64(key)

	// Get subkeys
	keys := ks(keyU)

	return &des{keys}
}

func (d *des) BlockSize() int {
	return BlockSize
}

func (d *des) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		log.Panic("cipher: src too short")
	}
	if len(dst) < BlockSize {
		log.Panic("cipher: dst too short")
	}

	// Apply permutation
	srcUint := binary.BigEndian.Uint64(src)
	preoutput := applyPermutation(srcUint, 64, ip[:])

	// Split into l and r
	l := uint32((preoutput >> 32) & Mask32)
	r := uint32(preoutput & Mask32)

	var lp, rp uint32 = 0, 0

	// Do Feistel cipher
	for _, key := range d.keys {
		lp = r
		rp = l ^ f(r, key)

		l = lp
		r = rp

	}

	// Put l and r together
	res := (uint64(r) << 32) | uint64(l)

	// Apply the IP inverse permutation
	res = applyPermutation(res, 64, ipInv[:])

	binary.BigEndian.PutUint64(dst, res)
}

func (d *des) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		log.Panic("cipher: src too short")
	}
	if len(dst) < BlockSize {
		log.Panic("cipher: dst too short")
	}

	// Apply permutation
	srcUint := binary.BigEndian.Uint64(src)
	preoutput := applyPermutation(srcUint, 64, ip[:])

	// Split into l and r
	rp := uint32((preoutput >> 32) & Mask32)
	lp := uint32(preoutput & Mask32)

	var l, r uint32 = 0, 0

	// Do feistel
	for i := range d.keys {
		key := d.keys[len(d.keys)-1-i]

		r = lp
		l = rp ^ f(lp, key)

		lp = l
		rp = r

	}

	res := (uint64(l) << 32) | uint64(r)

	res = applyPermutation(res, 64, ipInv[:])

	binary.BigEndian.PutUint64(dst, res)
}

type tdes struct {
	des1, des2, des3 cipher.Block
}

// NewTriple creates a new 3-DES cipher.
// key contains 3 64-bit keys.
func NewTriple(key []byte) cipher.Block {
	des1 := New(key[:8])
	des2 := New(key[8:16])
	des3 := New(key[16:])

	return &tdes{des1, des2, des3}
}

func (d *tdes) BlockSize() int {
	return BlockSize
}

func (d *tdes) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		log.Panic("cipher: src too short")
	}
	if len(dst) < BlockSize {
		log.Panic("cipher: dst too short")
	}

	d.des1.Encrypt(dst, src)
	d.des2.Decrypt(dst, dst)
	d.des3.Encrypt(dst, dst)
}

func (d *tdes) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		log.Panic("cipher: src too short")
	}
	if len(dst) < BlockSize {
		log.Panic("cipher: dst too short")
	}

	d.des3.Decrypt(dst, src)
	d.des2.Encrypt(dst, dst)
	d.des1.Decrypt(dst, dst)
}

// applyPermutation applies a permutation on the bits of src
// using table.
func applyPermutation(src uint64, srcLen int, table []int) uint64 {
	var res uint64 = 0

	for i, n := range table {
		// they number from the last bit
		newI := srcLen - n
		res = placeBit(src, res, newI, len(table)-1-i)
	}

	return res
}

// ks is the key schedule function.
// key is 64 bits.
// Output is the array of the 48 bits keys.
func ks(key uint64) [16]uint64 {
	// Initial permutation
	// keyP is 56 bits
	keyP := applyPermutation(key, 64, pc1[:])

	// Clear top bits
	keyP &= Mask56

	c := (keyP >> 28) & Mask28
	d := keyP & Mask28

	var cd uint64 = 0

	keys := make([]uint64, 16)

	for i := 0; i < 16; i++ {
		// Left shift and cycle back the bits
		shift := leftShifts[i]

		c <<= shift
		c |= c >> 28

		d <<= shift
		d |= d >> 28

		// Apply mask
		c &= Mask28
		d &= Mask28

		cd = (c << 28) | d

		keys[i] = applyPermutation(cd, 56, pc2[:])
	}

	return [16]uint64(keys)
}

// f is the f function in the DES algorithm.
// r is 32 bits.
// k is a 48 bit key.
func f(r uint32, k uint64) uint32 {
	// Compute e
	e := applyPermutation(uint64(r), 32, eTable[:])

	//fmt.Printf("E    = %048b\n", e)

	added := e ^ k

	//fmt.Printf("E+K  = %048b\n", added)
	var outS uint32 = 0

	// For each block of 6 bits
	for i := 0; i < 8; i++ {
		b := (added >> (6 * (8 - uint64(i) - 1))) & 0b111111
		bi, bj := getIj(uint8(b))
		sRes := getSij(bi, bj, sTables[i])

		outS |= uint32(sRes) << (4 * (8 - uint32(i) - 1))
	}

	//fmt.Printf("outS = %032b\n", outS)

	res := applyPermutation(uint64(outS), 32, p[:])

	//fmt.Printf("f    = %032b\n", res)

	//fmt.Println()
	return uint32(res)
}

// getSij gets the 4 bits value from a s matrix
func getSij(i, j uint8, s [64]uint8) uint8 {
	return s[i*16+j]
}

// getIj gets the indices for the S tables.
// b is 6 bits
func getIj(b uint8) (uint8, uint8) {
	i := ((b >> 4) & 0b10) | (b & 1)
	j := (b >> 1) & 0b1111

	return i, j
}

// placeBit places a bit from src into dst at the specified indices.
func placeBit(src, dst uint64, iSrc, iDst int) uint64 {
	bitSrc := (src >> iSrc) & 1

	if bitSrc == 1 {
		// clear bit
		dst &= Mask64 ^ (1 << iDst)
		// set bit
		dst |= bitSrc << iDst
	}

	return dst
}
