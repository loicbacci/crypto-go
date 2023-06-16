package bitarray

import (
	"errors"
	"strconv"
)

type BitArray interface {
	Size() int
	//SwitchBits() int

	// Get returns the bit at index pos
	Get(pos int) (int, error)

	//Set() int
	//Clear() int
	//
	//GetBuffer() []uint64
	//ToUint64() uint64

	String() string
}

type bitarray struct {
	buf  []uint64
	size int
}

func New(size int) BitArray {
	var bufSize int = (size / 64) + 1

	buf := make([]uint64, bufSize)

	return &bitarray{buf, size}
}

func (b *bitarray) Size() int {
	return b.size
}

func (b *bitarray) Get(pos int) (int, error) {
	if pos >= b.size {
		return 0, errors.New("bitarray: pos out of bounds")
	}
	block := b.buf[pos/64]
	res := (block >> (pos % 64)) & 1

	return int(res), nil
}

func (b *bitarray) String() string {
	res := ""
	for i := range b.buf {
		res = strconv.FormatInt(int64(b.buf[i]), 2) + res
	}

	return res
}
