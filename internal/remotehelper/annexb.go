package remotehelper

import "io"

// splitAccessUnits reads an H.264 stream in Annex B form (start codes, as an encoder writes it to a pipe) and calls emit
// for each access unit, that is for each picture. The encoder is asked for an access-unit delimiter in front of every
// picture, so a unit ends where the next delimiter begins. key says whether the unit holds an IDR slice (a picture a
// decoder can start from). emit returning false stops the reading.
func splitAccessUnits(r io.Reader, emit func(unit []byte, key bool) bool) error {
	const readSize = 64 << 10
	var buf []byte
	scanned := 0 // everything before this offset is known to hold no delimiter that starts a later unit
	chunk := make([]byte, readSize)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			next := nextDelimiter(buf, scanned)
			if next < 0 {
				// The last three bytes may be the start of a start code that the next read completes.
				if len(buf) > 3 {
					scanned = len(buf) - 3
				}
				break
			}
			if next > 0 {
				unit := append([]byte(nil), buf[:next]...)
				if !emit(unit, hasIDR(unit)) {
					return nil
				}
			}
			buf = buf[next:]
			scanned = 4
			if len(buf) < 4 {
				scanned = 0
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// nextDelimiter finds the start of the next access-unit delimiter NAL (type 9) at or after from, as the offset of its
// start code (00 00 01, with any zero byte before it included), or -1.
func nextDelimiter(b []byte, from int) int {
	if from < 1 {
		from = 1
	}
	for i := from; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 && b[i+3]&0x1f == 9 {
			if i > 0 && b[i-1] == 0 {
				return i - 1
			}
			return i
		}
	}
	return -1
}

// hasIDR says whether the unit holds an instantaneous decoder refresh slice (NAL type 5).
func hasIDR(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 && b[i+3]&0x1f == 5 {
			return true
		}
	}
	return false
}
