package asn1

import "bytes"

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
