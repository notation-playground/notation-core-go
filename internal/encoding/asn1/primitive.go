package asn1

// primitiveValue represents a value in primitive encoding.
type primitiveValue struct {
	identifier readOnlySlice
	content    readOnlySlice
}

// newPrimitiveValue builds the primitive value.
func newPrimitiveValue(identifier readOnlySlice, content readOnlySlice) value {
	return primitiveValue{
		identifier: identifier,
		content:    content,
	}
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
