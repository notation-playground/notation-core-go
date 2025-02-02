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

package asn1

import (
	"encoding/asn1"
	"reflect"
	"testing"
)

func TestConvertToDER(t *testing.T) {
	type data struct {
		Type  asn1.ObjectIdentifier
		Value []byte
	}

	want := data{
		Type: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
		Value: []byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
	}

	ber := []byte{
		// Constructed value
		0x30,
		// Constructed value length
		0x2e,

		// Type identifier
		0x06,
		// Type length
		0x09,
		// Type content
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,

		// Value identifier
		0x04,
		// Value length in BER
		0x81, 0x20,
		// Value content
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	}

	der, err := ConvertToDER(ber)
	if err != nil {
		t.Errorf("ConvertToDER() error = %v", err)
		return
	}

	var got data
	rest, err := asn1.Unmarshal(der, &got)
	if err != nil {
		t.Errorf("Failed to decode converted data: %v", err)
		return
	}
	if len(rest) > 0 {
		t.Errorf("Unexpected rest data: %v", rest)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got = %v, want %v", got, want)
	}
}
