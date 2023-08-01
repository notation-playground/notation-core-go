package asn1

import "bytes"

// constructedValue represents a value in constructed encoding.
type constructedValue struct {
	identifier []byte
	length     int
	members    []value
}

// newConstructedValue builds the constructed value.
func newConstructedValue(identifier []byte, content []byte) (value, error) {
	var (
		members []value
		value   value
		err     error
	)
	encodedLength := 0
	for len(content) > 0 {
		value, content, err = decode(content)
		if err != nil {
			return nil, err
		}
		members = append(members, value)
		encodedLength += value.EncodedLen()
	}

	return constructedValue{
		identifier: identifier,
		length:     encodedLength,
		members:    members,
	}, nil
}

// Encode encodes the constructed value to the value writer in DER.
func (v constructedValue) Encode(w *bytes.Buffer) error {
	_, err := w.Write(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLen(w, v.length); err != nil {
		return err
	}
	for _, value := range v.members {
		if err = value.Encode(w); err != nil {
			return err
		}
	}
	return nil
}

// EncodedLen returns the length in bytes of the encoded data.
func (v constructedValue) EncodedLen() int {
	return len(v.identifier) + encodedLenSize(v.length) + v.length
}
