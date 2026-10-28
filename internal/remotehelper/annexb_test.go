package remotehelper

import (
	"bytes"
	"testing"
	"testing/iotest"
)

func TestAccessUnitsAreSplitAtDelimitersWhateverTheReadSize(t *testing.T) {
	aud := []byte{0, 0, 0, 1, 0x09, 0xf0}
	idr := []byte{0, 0, 0, 1, 0x65, 1, 2, 3}
	delta := []byte{0, 0, 1, 0x41, 4, 5}
	stream := bytes.Join([][]byte{aud, idr, aud, delta, aud, delta}, nil)
	var got [][]byte
	var keys []bool
	// One byte at a time is the worst case: start codes arrive in pieces.
	err := splitAccessUnits(iotest.OneByteReader(bytes.NewReader(stream)), func(u []byte, key bool) bool {
		got = append(got, u)
		keys = append(keys, key)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	// The last unit has no delimiter after it yet, so it is not complete and is not emitted.
	if len(got) != 2 || !bytes.Equal(got[0], append(append([]byte{}, aud...), idr...)) || !keys[0] || keys[1] {
		t.Fatalf("%d units, keys %v", len(got), keys)
	}
}
