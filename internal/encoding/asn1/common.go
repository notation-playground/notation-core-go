package asn1

import (
	"bytes"
)

// encodeLen encodes length octets in DER.
func encodeLen(w *bytes.Buffer, length int) error {
	// DER restriction: short form must be used for length less than 128
	if length < 0x80 {
		return w.WriteByte(byte(length))
	}

	// DER restriction: long form must be encoded in the minimum number of octets
	lengthSize := encodedLenSize(length)
	err := w.WriteByte(0x80 | byte(lengthSize-1))
	if err != nil {
		return err
	}
	for i := lengthSize - 1; i > 0; i-- {
		if err = w.WriteByte(byte(length >> (8 * (i - 1)))); err != nil {
			return err
		}
	}
	return nil
}

// encodedLenSize gives the number of octets used for encoding the length.
func encodedLenSize(length int) int {
	if length < 0x80 {
		return 1
	}

	lengthSize := 1
	for ; length > 0; lengthSize++ {
		length >>= 8
	}
	return lengthSize
}
