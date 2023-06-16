package main

import (
	"github.com/loicbacciga/crypto-go/src/hash/sha1"
)

func main() {
	data := []byte("abc")
	h := sha1.New()
	h.Write(data)
	h.Sum(nil)
}
