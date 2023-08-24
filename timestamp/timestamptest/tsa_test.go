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

package timestamptest

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/internal/crypto/cms/oid"
	"github.com/notaryproject/notation-core-go/internal/crypto/cms/pki"
	"github.com/notaryproject/notation-core-go/timestamp"
)

func TestTSATimestampGranted(t *testing.T) {
	// prepare TSA
	now := time.Date(2021, 9, 18, 11, 54, 34, 0, time.UTC)
	tsa, err := NewTSA()
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}
	tsa.NowFunc = func() time.Time {
		return now
	}

	// do timestamp
	message := []byte("notation")
	req, err := timestamp.NewRequestFromContent(message, crypto.SHA256)
	if err != nil {
		t.Fatalf("NewRequestFromContent() error = %v", err)
	}
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusGranted
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}

	// verify timestamp token
	token, err := resp.SignedToken()
	if err != nil {
		t.Fatalf("Response.SignedToken() error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tsa.Certificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := token.Verify(opts); err != nil {
		t.Fatal("SignedToken.Verify() error =", err)
	}
	info, err := token.Info()
	if err != nil {
		t.Fatal("SignedToken.Info() error =", err)
	}
	if err := info.VerifyContent(message); err != nil {
		t.Errorf("TSTInfo.Verify() error = %v", err)
	}
	ts, accuracy := info.Timestamp()
	wantTimestamp := now
	if ts != wantTimestamp {
		t.Errorf("TSTInfo.Timestamp() Timestamp = %v, want %v", ts, wantTimestamp)
	}
	wantAccuracy := time.Second
	if accuracy != wantAccuracy {
		t.Errorf("TSTInfo.Timestamp() Accuracy = %v, want %v", accuracy, wantAccuracy)
	}
}

func TestTSATimestampRejection(t *testing.T) {
	// prepare TSA
	tsa, err := NewTSA()
	if err != nil {
		t.Fatalf("NewTSA() error = %v", err)
	}

	// do timestamp
	message := []byte("notation")
	req, err := timestamp.NewRequestFromContent(message, crypto.SHA256)
	if err != nil {
		t.Fatalf("NewRequestFromContent() error = %v", err)
	}
	req.MessageImprint.HashAlgorithm.Algorithm = oid.SHA1WithRSA // set bad algorithm
	ctx := context.Background()
	resp, err := tsa.Timestamp(ctx, req)
	if err != nil {
		t.Fatalf("TSA.Timestamp() error = %v", err)
	}
	wantStatus := pki.StatusRejection
	if got := resp.Status.Status; got != wantStatus {
		t.Fatalf("Response.Status = %v, want %v", got, wantStatus)
	}
}
