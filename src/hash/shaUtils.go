package hash

import (
	"encoding/binary"
	"math/big"
)

// Padding

func ShaPadding32(l *big.Int) []byte {
	res := make([]byte, 0)

	// l is length of the message in bits
	li := l.Uint64()
	k := (448 - 1 - li) % 512

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
	binary.BigEndian.PutUint64(lBytes, li)
	res = append(res, lBytes...)

	return res
}
