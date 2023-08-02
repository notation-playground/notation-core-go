package asn1

import "bytes"

// constructedValue represents a value in constructed encoding.
type constructedValue struct {
	identifier  []byte
	expectedLen int
	length      int
	members     []value
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
