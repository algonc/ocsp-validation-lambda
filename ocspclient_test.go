// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package ocspclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// -------------------- Helpers --------------------

// generateSelfSignedCert generates a self-signed certificate and returns DER bytes + private key
func generateSelfSignedCert(t *testing.T, serial int64, ocspURL string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	if ocspURL != "" {
		template.OCSPServer = []string{ocspURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}
	return der, priv
}

// writeTempPEM writes one or more DER certs to a temporary PEM file
func writeTempPEM(t *testing.T, certs ...[]byte) string {
	t.Helper()
	var data []byte
	for _, der := range certs {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		data = append(data, pem.EncodeToMemory(block)...)
	}
	tmp := t.TempDir() + "/cert.pem"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatalf("write temp PEM failed: %v", err)
	}
	return tmp
}

// -------------------- Mock HTTP client --------------------

type mockHTTPClient struct {
	respBody []byte
	status   int
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
	}, nil
}

// -------------------- Minimal valid OCSP response --------------------

func generateOCSPResponse(t *testing.T, leaf, issuer *x509.Certificate, issuerPriv *rsa.PrivateKey) []byte {
	t.Helper()
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	der, err := ocsp.CreateResponse(issuer, leaf, template, issuerPriv)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}
	return der
}

// -------------------- Tests --------------------

func TestFetchStaple_Base64(t *testing.T) {
	ocspURL := "http://mock.ocsp.server/ocsp"
	leafDER, _ := generateSelfSignedCert(t, 1, ocspURL)
	issuerDER, issuerPriv := generateSelfSignedCert(t, 2, ocspURL)

	leafCert, _ := x509.ParseCertificate(leafDER)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	ocspResp := generateOCSPResponse(t, leafCert, issuerCert, issuerPriv)

	client := New(Config{
		HTTPClient: &mockHTTPClient{
			respBody: ocspResp,
			status:   http.StatusOK,
		},
		Now: time.Now,
	})

	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerDER)

	resp, err := client.FetchStaple(context.Background(), WithBase64Certs([]string{leafB64, issuerB64}))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !bytes.Equal(resp, ocspResp) {
		t.Fatalf("expected OCSP response bytes to match")
	}
}

func TestFetchStaple_PEM(t *testing.T) {
	ocspURL := "http://mock.ocsp.server/ocsp"
	leafDER, _ := generateSelfSignedCert(t, 3, ocspURL)
	issuerDER, issuerPriv := generateSelfSignedCert(t, 4, ocspURL)

	leafCert, _ := x509.ParseCertificate(leafDER)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	ocspResp := generateOCSPResponse(t, leafCert, issuerCert, issuerPriv)

	pemFile := writeTempPEM(t, leafDER, issuerDER)

	client := New(Config{
		HTTPClient: &mockHTTPClient{
			respBody: ocspResp,
			status:   http.StatusOK,
		},
		Now: time.Now,
	})

	resp, err := client.FetchStaple(context.Background(), WithPEMPaths([]string{pemFile}))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !bytes.Equal(resp, ocspResp) {
		t.Fatalf("expected OCSP response bytes to match")
	}
}

func TestFetchStaple_NoOCSP(t *testing.T) {
	// Certificates without OCSPServer
	leafDER, _ := generateSelfSignedCert(t, 5, "")
	issuerDER, _ := generateSelfSignedCert(t, 6, "")

	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerDER)

	client := New(Config{
		HTTPClient: &mockHTTPClient{
			respBody: []byte("dummy"),
			status:   http.StatusOK,
		},
	})

	_, err := client.FetchStaple(context.Background(), WithBase64Certs([]string{leafB64, issuerB64}))
	if err == nil || err.Error() != "no OCSP endpoint found" {
		t.Fatalf("expected 'no OCSP endpoint found', got %v", err)
	}
}

func TestFetchStaple_InvalidPEM(t *testing.T) {
	tmp := t.TempDir() + "/bad.pem"
	os.WriteFile(tmp, []byte("not a pem"), 0644)

	client := New(Config{})

	_, err := client.FetchStaple(context.Background(), WithPEMPaths([]string{tmp}))
	if err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestFetchStaple_HTTPError(t *testing.T) {
	ocspURL := "http://mock.ocsp.server/ocsp"
	leafDER, _ := generateSelfSignedCert(t, 7, ocspURL)
	issuerDER, _ := generateSelfSignedCert(t, 8, ocspURL)

	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerDER)

	client := New(Config{
		HTTPClient: &mockHTTPClient{
			err: errors.New("network error"),
		},
		MaxRetries: 1, // optional: reduce retries for test speed
	})

	_, err := client.FetchStaple(context.Background(), WithBase64Certs([]string{leafB64, issuerB64}))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("network error")) {
		t.Fatalf("expected error to contain 'network error', got %v", err)
	}
}

func TestFetchStaple_EmptyOptions(t *testing.T) {
	client := New(Config{})
	_, err := client.FetchStaple(context.Background())
	if err == nil {
		t.Fatalf("expected error when no options provided")
	}
}
