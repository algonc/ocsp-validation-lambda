// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/algonc/ocspclient"
)

// -------------------- Mock OCSPFetcher --------------------

type mockFetcher struct {
	resp []byte
	err  error
}

func (m *mockFetcher) FetchStaple(ctx context.Context, opts ...ocspclient.FetchOption) ([]byte, error) {
	return m.resp, m.err
}

// -------------------- Tests --------------------

func TestHandler_Success(t *testing.T) {
	// fake OCSP response
	mockResp := []byte("fake-ocsp-response")

	// inject mock
	client = &mockFetcher{resp: mockResp, err: nil}

	req := Request{
		Base64CertChain: []string{
			base64.StdEncoding.EncodeToString([]byte("leaf-cert")),
			base64.StdEncoding.EncodeToString([]byte("issuer-cert")),
		},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := base64.StdEncoding.EncodeToString(mockResp)
	if resp.OCSPResponseBase64 != expected {
		t.Fatalf("expected %s, got %s", expected, resp.OCSPResponseBase64)
	}
}

func TestHandler_ErrorNotEnoughCerts(t *testing.T) {
	client = &mockFetcher{} // won't be called

	req := Request{
		Base64CertChain: []string{
			base64.StdEncoding.EncodeToString([]byte("only-leaf")),
		},
	}

	_, err := handler(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for chain with less than 2 certs")
	}
}

func TestHandler_ErrorFromFetcher(t *testing.T) {
	client = &mockFetcher{
		resp: nil,
		err:  errors.New("OCSP fetch failed"),
	}

	req := Request{
		Base64CertChain: []string{
			base64.StdEncoding.EncodeToString([]byte("leaf")),
			base64.StdEncoding.EncodeToString([]byte("issuer")),
		},
	}

	_, err := handler(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from mock fetcher")
	}
}
