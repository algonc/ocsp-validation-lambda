// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

type mockClient struct {
	resp []byte
	err  error
}

func (m *mockClient) FetchStaple(ctx context.Context, chain []string) ([]byte, error) {
	return m.resp, m.err
}

func TestHandler_Success(t *testing.T) {
	originalClient := client
	defer func() { client = originalClient }()

	expectedBytes := []byte("ocsp-response")
	client = &mockClient{
		resp: expectedBytes,
		err:  nil,
	}

	req := Request{
		CertChain: []string{"leaf", "issuer"},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedB64 := base64.StdEncoding.EncodeToString(expectedBytes)

	if resp.OCSPResponseBase64 != expectedB64 {
		t.Fatalf("expected %s, got %s", expectedB64, resp.OCSPResponseBase64)
	}
}

func TestHandler_Error(t *testing.T) {
	originalClient := client
	defer func() { client = originalClient }()

	client = &mockClient{
		err: errors.New("fetch failed"),
	}

	req := Request{
		CertChain: []string{"leaf", "issuer"},
	}

	resp, err := handler(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error")
	}

	if resp.OCSPResponseBase64 != "" {
		t.Fatalf("expected empty response")
	}
}
