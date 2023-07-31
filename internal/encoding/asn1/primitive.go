package asn1

// PrimitiveValue represents a value in primitive encoding.
type PrimitiveValue struct {
	identifier ReadOnlySlice
	content    ReadOnlySlice
}

// newPrimitiveValue builds the primitive value.
func newPrimitiveValue(identifier ReadOnlySlice, content ReadOnlySlice) (Value, error) {
	return PrimitiveValue{
		identifier: identifier,
		content:    content,
	}, nil
}

// Encode encodes the primitive value to the value writer in DER.
func (v PrimitiveValue) Encode(w ValueWriter) error {
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
func (v PrimitiveValue) EncodedLen() int {
	return v.identifier.Length() + encodedLengthSize(v.content.Length()) + v.content.Length()
}
