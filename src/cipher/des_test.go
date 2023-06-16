package des

import (
	godes "crypto/des"
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"testing"
)

func TestPlaceBit(t *testing.T) {
	src, _ := strconv.ParseUint("1101", 2, 8)
	dst, _ := strconv.ParseUint("1100", 2, 8)
	iSrc := 0
	iDst := 1

	exp, _ := strconv.ParseUint("1110", 2, 8)

	res := placeBit(src, dst, iSrc, iDst)

	if res != exp {
		t.Error()
	}
}

func TestApplyPermutation(t *testing.T) {
	n, _ := strconv.ParseUint("1100", 2, 8)
	table := []int{3, 4, 1, 2}

	exp, _ := strconv.ParseUint("0011", 2, 8)

	res := applyPermutation(n, 4, table)

	if res != exp {
		t.Errorf("%b != %b", res, exp)
	}
}

func TestKS(t *testing.T) {
	var key uint64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001

	exp := []uint64{
		0b000110_110000_001011_101111_111111_000111_000001_110010,
		0b011110_011010_111011_011001_110110_111100_100111_100101,
		0b010101_011111_110010_001010_010000_101100_111110_011001,
		0b011100_101010_110111_010110_110110_110011_010100_011101,
		0b011111_001110_110000_000111_111010_110101_001110_101000,
		0b011000_111010_010100_111110_010100_000111_101100_101111,
		0b111011_001000_010010_110111_111101_100001_100010_111100,
		0b111101_111000_101000_111010_110000_010011_101111_111011,
		0b111000_001101_101111_101011_111011_011110_011110_000001,
		0b101100_011111_001101_000111_101110_100100_011001_001111,
		0b001000_010101_111111_010011_110111_101101_001110_000110,
		0b011101_010111_000111_110101_100101_000110_011111_101001,
		0b100101_111100_010111_010001_111110_101011_101001_000001,
		0b010111_110100_001110_110111_111100_101110_011100_111010,
		0b101111_111001_000110_001101_001111_010011_111100_001010,
		0b110010_110011_110110_001011_000011_100001_011111_110101,
	}

	res := ks(key)

	for i := range res {
		if res[i] != exp[i] {
			t.Errorf("%b != %b", res[i], exp[i])
		}
	}
}

func TestEncrypt(t *testing.T) {
	var key uint64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001
	keyB := make([]byte, 8)
	binary.BigEndian.PutUint64(keyB, key)

	var m uint64 = 0x0123456789ABCDEF
	mB := make([]byte, 8)
	binary.BigEndian.PutUint64(mB, m)

	cB := make([]byte, 8)

	des := New(keyB)
	des.Encrypt(cB, mB)

	c := binary.BigEndian.Uint64(cB)
	var expC uint64 = 0x85E813540F0AB405

	if c != expC {
		t.Error()
	}
}

func TestDecrypt(t *testing.T) {
	var key uint64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001
	keyB := make([]byte, 8)
	binary.BigEndian.PutUint64(keyB, key)

	var c uint64 = 0x85E813540F0AB405
	cB := make([]byte, 8)
	binary.BigEndian.PutUint64(cB, c)

	mB := make([]byte, 8)

	des := New(keyB)
	des.Decrypt(mB, cB)

	m := binary.BigEndian.Uint64(mB)
	var expM uint64 = 0x0123456789ABCDEF

	if m != expM {
		t.Error()
	}
}

func TestEncryptGo(t *testing.T) {
	var key uint64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001
	keyB := make([]byte, 8)
	binary.BigEndian.PutUint64(keyB, key)

	goDes, _ := godes.NewCipher(keyB)
	des := New(keyB)

	m := make([]byte, 8)
	_, err := rand.Read(m)

	if err != nil {
		t.Fatalf("m error")
	}

	goDst := make([]byte, 8)
	dst := make([]byte, 8)

	goDes.Encrypt(goDst, m)
	des.Encrypt(dst, m)

	for i := range dst {
		if dst[i] != goDst[i] {
			t.Fatalf("Not the same")
		}
	}
}

func TestDecryptGo(t *testing.T) {
	var key uint64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001
	keyB := make([]byte, 8)
	binary.BigEndian.PutUint64(keyB, key)

	goDes, _ := godes.NewCipher(keyB)
	des := New(keyB)

	m := make([]byte, 8)
	_, err := rand.Read(m)

	if err != nil {
		t.Fatalf("m error")
	}

	goDst := make([]byte, 8)
	dst := make([]byte, 8)

	goDes.Decrypt(goDst, m)
	des.Decrypt(dst, m)

	for i := range dst {
		if dst[i] != goDst[i] {
			t.Fatalf("Not the same")
		}
	}
}

func TestTDES(t *testing.T) {
	keyB := make([]byte, 8*3)
	_, err := rand.Read(keyB)

	if err != nil {
		t.Fatalf("key error")
	}

	m := make([]byte, 8)
	_, err = rand.Read(m)

	if err != nil {
		t.Fatalf("m error")
	}

	goTdes, _ := godes.NewTripleDESCipher(keyB)
	tdes := NewTriple(keyB)

	goDst := make([]byte, 8)
	dst := make([]byte, 8)

	// Test encryption
	goTdes.Encrypt(goDst, m)
	tdes.Encrypt(dst, m)

	for i := range dst {
		if dst[i] != goDst[i] {
			t.Fatalf("Not the same")
		}
	}

	// Test decryption
	c := make([]byte, 8)
	_, err = rand.Read(c)

	if err != nil {
		t.Fatalf("c error")
	}

	goTdes.Decrypt(goDst, c)
	tdes.Decrypt(dst, c)

	for i := range dst {
		if dst[i] != goDst[i] {
			t.Fatalf("Not the same")
		}
	}
}

func TestGetIj(t *testing.T) {
	var n uint8 = 0b110101
	var iExp uint8 = 0b11
	var jExp uint8 = 0b1010

	i, j := getIj(n)

	if i != iExp || j != jExp {
		t.Error()
	}
}

func TestGetSij(t *testing.T) {
	var b uint8 = 0b011011
	i, j := getIj(b)

	var exp uint8 = 0b0101

	res := getSij(i, j, s1)

	if res != exp {
		t.Error()
	}
}
