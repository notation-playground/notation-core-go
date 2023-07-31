// Package asn1 decodes BER-encoded ASN.1 data structures and encodes in DER.
// Note: DER is a subset of BER.
// Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html
package asn1

import (
	"bytes"
	"encoding/asn1"
	"io"
)

// Common errors
var (
	ErrEarlyEOF          = asn1.SyntaxError{Msg: "early EOF"}
	ErrExpectConstructed = asn1.SyntaxError{Msg: "constructed value expected"}
	ErrExpectPrimitive   = asn1.SyntaxError{Msg: "primitive value expected"}
	ErrUnsupportedLength = asn1.StructuralError{Msg: "length method not supported"}
	ErrInvalidSlice      = asn1.StructuralError{Msg: "invalid slice"}
	ErrInvalidOffset     = asn1.StructuralError{Msg: "invalid offset"}
)

// value represents an ASN.1 value.
type value interface {
	// Encode encodes the value to the value writer in DER.
	Encode(valueWriter) error

	// EncodedLen returns the length in bytes of the encoded data.
	EncodedLen() int
}

// ConvertToDER converts BER-encoded ASN.1 data structures to DER-encoded.
func ConvertToDER(ber []byte) ([]byte, error) {
	v, err := decode(newReadOnlySlice(ber))
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, v.EncodedLen()))
	if err = v.Encode(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decode decodes BER-encoded ASN.1 data structures.
func decode(r ReadOnlySlice) (value, error) {
	identifier, isPrimitiveValue, err := identifierValue(r)
	if err != nil {
		return nil, err
	}
	expectedLength, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	content, err := r.Slice(r.Offset(), r.Offset()+expectedLength)
	if err != nil {
		return nil, err
	}
	if err = r.Seek(r.Offset() + expectedLength); err != nil {
		return nil, err
	}

	if isPrimitiveValue {
		return newPrimitiveValue(identifier, content)
	}
	return newConstructedValue(identifier, expectedLength, content)
}

// identifierValue decodes identifierValue octets.
func identifierValue(r ReadOnlySlice) (ReadOnlySlice, bool, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, false, err
	}
	isPrimitiveValue := isPrimitive(b)

	tagBytesCount := 1
	// high-tag-number form
	if b&0x1f == 0x1f {
		for {
			b, err = r.ReadByte()
			if err != nil {
				return nil, false, err
			}
			tagBytesCount++
			if b&0x80 != 0 {
				break
			}
		}
	}

	identifier, err := r.Slice(r.Offset()-tagBytesCount, r.Offset())
	if err != nil {
		return nil, false, err
	}
	return identifier, isPrimitiveValue, nil
}

// isPrimitive checks the primitive flag in the identifier.
// Returns true if the value is primitive.
func isPrimitive(identifier byte) bool {
	return identifier&0x20 == 0
}

// decodeLength decodes length octets.
// Indefinite length is not supported
func decodeLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch {
	case b < 0x80:
		// short form
		return int(b), nil
	case b == 0x80:
		// Indefinite-length method is not supported.
		return 0, ErrUnsupportedLength
	}

	// long form
	n := int(b & 0x7f)
	if n > 4 {
		// length must fit the memory space of the int type.
		return 0, ErrUnsupportedLength
	}
	var length int
	for i := 0; i < n; i++ {
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		length = (length << 8) | int(b)
	}
	if length < 0 {
		// double check in case that length is over 31 bits.
		return 0, ErrUnsupportedLength
	}
	return length, nil
}
