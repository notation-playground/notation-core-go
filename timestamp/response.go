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

package timestamp

import (
	"encoding/asn1"
	"errors"

	"github.com/notaryproject/notation-core-go/internal/crypto/cms/pki"
)

// Response is a time-stamping response.
//
//	TimeStampResp ::= SEQUENCE {
//	 status          PKIStatusInfo,
//	 timeStampToken  TimeStampToken  OPTIONAL }
type Response struct {
	Status         pki.StatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// MarshalBinary encodes the response to binary form.
// This method implements encoding.BinaryMarshaler
func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return asn1.Marshal(r)
}

// UnmarshalBinary decodes the response from binary form.
// This method implements encoding.BinaryUnmarshaler
func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// TokenBytes returns the bytes of the timestamp token.
func (r *Response) TokenBytes() []byte {
	return r.TimeStampToken.FullBytes
}

// SignedToken returns the timestamp token with signatures.
// Callers should invoke Verify to verify the content before comsumption.
func (r *Response) SignedToken() (*SignedToken, error) {
	return ParseSignedToken(r.TokenBytes())
}
