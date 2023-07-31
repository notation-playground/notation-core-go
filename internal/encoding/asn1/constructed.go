package asn1

// ConstructedValue represents a value in constructed encoding.
type ConstructedValue struct {
	identifier ReadOnlySlice
	length     int
	members    []Value
}

// newConstructedValue builds the constructed value.
func newConstructedValue(identifier ReadOnlySlice, expectedLength int, content ReadOnlySlice) (Value, error) {
	var members []Value
	encodedLength := 0
	for content.Offset() < content.Length() {
		value, err := decode(content)
		if err != nil {
			return nil, err
		}
		members = append(members, value)
		encodedLength += value.EncodedLen()
	}

	return ConstructedValue{
		identifier: identifier,
		length:     encodedLength,
		members:    members,
	}, nil
}

// Encode encodes the constructed value to the value writer in DER.
func (v ConstructedValue) Encode(w ValueWriter) error {
	_, err := w.ReadFrom(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLength(w, v.length); err != nil {
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
func (v ConstructedValue) EncodedLen() int {
	return v.identifier.Length() + encodedLengthSize(v.length) + v.length
}
