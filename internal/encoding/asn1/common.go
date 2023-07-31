package asn1

import "io"

// encodeLength encodes length octets in DER.
func encodeLength(w io.ByteWriter, length int) error {
	// DER restriction: short form must be used for length less than 128
	if length < 0x80 {
		return w.WriteByte(byte(length))
	}

	// DER restriction: long form must be encoded in the minimum number of octets
	lengthSize := encodedLengthSize(length)
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

// encodedLengthSize gives the number of octets used for encoding the length.
func encodedLengthSize(length int) int {
	if length < 0x80 {
		return 1
	}

	lengthSize := 1
	for ; length > 0; lengthSize++ {
		length >>= 8
	}
	return lengthSize
}
