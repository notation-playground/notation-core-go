package asn1

// primitiveValue represents a value in primitive encoding.
type primitiveValue struct {
	identifier ReadOnlySlice
	content    ReadOnlySlice
}

// newPrimitiveValue builds the primitive value.
func newPrimitiveValue(identifier ReadOnlySlice, content ReadOnlySlice) (value, error) {
	return primitiveValue{
		identifier: identifier,
		content:    content,
	}, nil
}

// Encode encodes the primitive value to the value writer in DER.
func (v primitiveValue) Encode(w valueWriter) error {
	_, err := w.ReadFrom(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLength(w, v.content.Length()); err != nil {
		return err
	}
	_, err = w.ReadFrom(v.content)
	return err
}

// EncodedLen returns the length in bytes of the encoded data.
func (v primitiveValue) EncodedLen() int {
	return v.identifier.Length() + encodedLengthSize(v.content.Length()) + v.content.Length()
}
