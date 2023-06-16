package md2

import (
	"hash"
)

type digest struct {
	msg []byte
}

const BlockSize int = 16
const Size int = 16

var piSubst = [...]byte{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
}

// appendPadding appends the padding to the buffer
// c.f. RFC1319 3.1
func appendPadding(buf *[]byte) {
	// length must be multiple of 16
	// pad value i, i times
	padLen := BlockSize - (len(*buf) % BlockSize)

	padB := byte(padLen)

	for i := 0; i < padLen; i++ {
		*buf = append(*buf, padB)
	}
}

// appendChecksum appends the checksum to the buffer
// c.f. RFC1319 3.2
func appendChecksum(buf *[]byte) {
	N := len(*buf)
	check := make([]byte, BlockSize)

	// Clear checksum
	for i := range check {
		check[i] = 0
	}

	var L byte = 0

	// Process each byte
	for i := 0; i < N/BlockSize; i++ {
		// Checksum block i
		for j := 0; j < BlockSize; j++ {
			c := (*buf)[i*16+j]
			// Don't know where ^ check[j] is mentionned but we need it
			check[j] = piSubst[c^L] ^ check[j]
			L = check[j]
		}
	}

	*buf = append(*buf, check...)
}

// processMessage computes the message digest
// c.f. RFC1319 3.3-3.4
func processMessage(buf *[]byte) [48]byte {
	// Step 3
	var X [48]byte
	for i := range X {
		X[i] = 0
	}

	// Step 4
	Nprime := len(*buf)

	// Process each 16B block
	for i := 0; i < Nprime/BlockSize; i++ {
		// Copy block i into X
		for j := 0; j < BlockSize; j++ {
			X[16+j] = (*buf)[i*16+j]
			X[32+j] = X[16+j] ^ X[j]
		}

		var t byte = 0

		// Do 18 rounds
		for j := 0; j < 18; j++ {
			// Round j
			for k := 0; k < 48; k++ {
				X[k] = X[k] ^ piSubst[t]
				t = X[k]
			}

			t = t + byte(j)
		}
	}

	return X
}

// Sum computes a hash of data using the Sum algorithm as defined
// in RFC 1319 (https://datatracker.ietf.org/doc/html/rfc1319)
func Sum(data []byte) [Size]byte {
	res := make([]byte, len(data))
	copy(res, data)
	// fmt.Println(hex.EncodeToString(res))

	// Step 1: append padding
	appendPadding(&res)
	// fmt.Println(hex.EncodeToString(res))

	// Step 2: append checksum
	appendChecksum(&res)
	// fmt.Println(hex.EncodeToString(res))

	// Step 3 & 4: initialize MD buffer & process message in 16B blocks
	X := processMessage(&res)
	// fmt.Println(hex.EncodeToString(X))

	return ([BlockSize]byte)(X[:BlockSize])
}

// Implement Hash

func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Write(p []byte) (n int, err error) {
	// Just append to the already written data
	d.msg = append(d.msg, p...)
	return
}

func (d *digest) Reset() {
	d.msg = nil
}

func (d *digest) Sum(b []byte) []byte {
	h := Sum(d.msg)
	return append(b, h[:]...)
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}
