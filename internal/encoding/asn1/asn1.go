// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	ErrBytesAtTheEnd           = asn1.StructuralError{Msg: "invalid bytes at the end of the BER data"}
	ErrEarlyEOF                = asn1.SyntaxError{Msg: "early EOF"}
	ErrInvalidBerData          = asn1.StructuralError{Msg: "invalid BER data"}
	ErrInvalidOffset           = asn1.StructuralError{Msg: "invalid offset"}
	ErrInvalidSlice            = asn1.StructuralError{Msg: "invalid slice"}
	ErrUnsupportedLen          = asn1.StructuralError{Msg: "length method not supported"}
	ErrUnsupportedIndefinedLen = asn1.StructuralError{Msg: "indefinite length not supported"}
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
	v, err := decode(ber)
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
func decode(r []byte) (value, error) {
	var (
		identifier  []byte
		contentLen  int
		berValueLen int
		isPrimitive bool
		err         error
	)
	// prepare the first value
	identifier, contentLen, _, isPrimitive, r, err = decodeMetadata(r)
	if err != nil {
		return nil, err
	}

	// primitive value
	if isPrimitive {
		if contentLen != len(r) {
			return nil, ErrBytesAtTheEnd
		}
		return primitiveValue{
			identifier: identifier,
			content:    r[:contentLen],
		}, nil
	}
	// constructed value
	rootConstructed := constructedValue{
		identifier:  identifier,
		expectedLen: contentLen,
	}

	// start depth-first decoding with stack
	valueStack := []*constructedValue{&rootConstructed}
	for len(valueStack) > 0 {
		stackLen := len(valueStack)
		// top
		v := valueStack[stackLen-1]

		if v.expectedLen < 0 {
			return nil, ErrInvalidBerData
		}

		if v.expectedLen == 0 {
			// calculate the length of the constructed value
			for _, m := range v.members {
				v.length += m.EncodedLen()
			}

			// pop the constructued value
			valueStack = valueStack[:stackLen-1]
			continue
		}

		for v.expectedLen > 0 {
			identifier, contentLen, berValueLen, isPrimitive, r, err = decodeMetadata(r)
			if err != nil {
				return nil, err
			}
			if isPrimitive {
				// primitive value
				pv := primitiveValue{
					identifier: identifier,
					content:    r[:contentLen],
				}
				r = r[contentLen:]
				v.expectedLen -= berValueLen
				v.members = append(v.members, &pv)
			} else {
				// constructed value
				cv := constructedValue{
					identifier:  identifier,
					expectedLen: contentLen,
				}
				v.expectedLen -= berValueLen
				v.members = append(v.members, &cv)
				valueStack = append(valueStack, &cv)
				// break to start decoding the new constructed value in the next
				// iteration
				break
			}
		}
	}
	if len(r) > 0 {
		return nil, ErrBytesAtTheEnd
	}
	return rootConstructed, nil
}

func decodeMetadata(r []byte) ([]byte, int, int, bool, []byte, error) {
	length := len(r)
	identifier, r, err := decodeIdentifier(r)
	if err != nil {
		return nil, 0, 0, false, nil, err
	}
	contentLen, r, err := decodeLen(r)
	if err != nil {
		return nil, 0, 0, false, nil, err
	}

	if contentLen > len(r) {
		return nil, 0, 0, false, nil, ErrEarlyEOF
	}
	isPrimitive := identifier[0]&0x20 == 0
	metadataLen := length - len(r)
	berValueLen := metadataLen + contentLen
	return identifier, contentLen, berValueLen, isPrimitive, r, nil
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

// decodeLen decodes length octets.
// Indefinite length is not supported
func decodeLen(r []byte) (int, []byte, error) {
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
