package asn1

import "bytes"

// primitiveValue represents a value in primitive encoding.
type primitiveValue struct {
	identifier []byte
	content    []byte
}

// Encode encodes the primitive value to the value writer in DER.
func (v primitiveValue) Encode(w *bytes.Buffer) error {
	_, err := w.Write(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLen(w, len(v.content)); err != nil {
		return err
	}
	_, err = w.Write(v.content)
	return err
}

// EncodedLen returns the length in bytes of the encoded data.
func (v primitiveValue) EncodedLen() int {
	return len(v.identifier) + encodedLenSize(len(v.content)) + len(v.content)
}
