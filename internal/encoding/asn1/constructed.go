package asn1

// constructedValue represents a value in constructed encoding.
type constructedValue struct {
	identifier readOnlySlice
	length     int
	members    []value
}

// newConstructedValue builds the constructed value.
func newConstructedValue(identifier readOnlySlice, content readOnlySlice) (value, error) {
	var members []value
	encodedLength := 0
	for content.Offset() < content.Length() {
		value, err := decode(content)
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
func (v constructedValue) Encode(w valueWriter) error {
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
func (v constructedValue) EncodedLen() int {
	return v.identifier.Length() + encodedLengthSize(v.length) + v.length
}
