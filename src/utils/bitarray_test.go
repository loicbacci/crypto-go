package bitarray

import "testing"

func TestGet(t *testing.T) {
	arr := New(8)

	r, err := arr.Get(5)

	if err != nil || r != 0 {
		t.Error()
	}
}
