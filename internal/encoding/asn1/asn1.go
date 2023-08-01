// Package asn1 decodes BER-encoded ASN.1 data structures and encodes in DER.
// Note: DER is a subset of BER.
// Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html
package asn1

import (
	"bytes"
	"encoding/asn1"
)

// Common errors
var (
	ErrEarlyEOF                = asn1.SyntaxError{Msg: "early EOF"}
	ErrUnsupportedLen          = asn1.StructuralError{Msg: "length method not supported"}
	ErrUnsupportedIndefinedLen = asn1.StructuralError{Msg: "indefinite length not supported"}
	ErrInvalidSlice            = asn1.StructuralError{Msg: "invalid slice"}
	ErrInvalidOffset           = asn1.StructuralError{Msg: "invalid offset"}
)

// value represents an ASN.1 value.
type value interface {
	// Encode encodes the value to the value writer in DER.
	Encode(*bytes.Buffer) error

	// EncodedLen returns the length in bytes of the encoded data.
	EncodedLen() int
}

// ConvertToDER converts BER-encoded ASN.1 data structures to DER-encoded.
func ConvertToDER(ber []byte) ([]byte, error) {
	v, _, err := decode(ber)
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
func decode(r []byte) (value, []byte, error) {
	identifier, r, err := decodeIdentifier(r)
	if err != nil {
		return nil, nil, err
	}
	contentLength, r, err := decodeLength(r)
	if err != nil {
		return nil, nil, err
	}

	if contentLength > len(r) {
		return nil, nil, ErrEarlyEOF
	}
	content := r[:contentLength]
	r = r[contentLength:]

	isPrimitive := identifier[0]&0x20 == 0
	// primitive value
	if isPrimitive {
		return newPrimitiveValue(identifier, content), r, nil
	}

	// constructed value
	v, err := newConstructedValue(identifier, content)
	if err != nil {
		return nil, nil, err
	}
	return v, r, nil
}

// decodeIdentifier decodes decodeIdentifier octets.
func decodeIdentifier(r []byte) ([]byte, []byte, error) {
	offset := 0
	if len(r) < 1 {
		return nil, nil, ErrEarlyEOF
	}
	b := r[offset]
	offset++

	// high-tag-number form
	if b&0x1f == 0x1f {
		for offset < len(r) && r[offset]&0x80 == 0x80 {
			offset++
		}
	}
	return r[:offset], r[offset:], nil
}

// decodeLength decodes length octets.
// Indefinite length is not supported
func decodeLength(r []byte) (int, []byte, error) {
	offset := 0
	if len(r) < 1 {
		return 0, nil, ErrEarlyEOF
	}
	b := r[offset]
	offset++
	switch {
	case b < 0x80:
		// short form
		return int(b), r[offset:], nil
	case b == 0x80:
		// Indefinite-length method is not supported.
		return 0, nil, ErrUnsupportedIndefinedLen
	}

	// long form
	n := int(b & 0x7f)
	if n > 4 {
		// length must fit the memory space of the int type.
		return 0, nil, ErrUnsupportedLen
	}
	var length int
	for i := 0; i < n; i++ {
		if offset >= len(r) {
			return 0, nil, ErrEarlyEOF
		}
		length = (length << 8) | int(r[offset])
		offset++
	}
	if length < 0 {
		// double check in case that length is over 31 bits.
		return 0, nil, ErrUnsupportedLen
	}
	return length, r[offset:], nil
}
