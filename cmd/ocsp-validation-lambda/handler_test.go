// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.


package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func generateTestCerts(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuerCert, _ := x509.ParseCertificate(issuerDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		OCSPServer: []string{
			"http://localhost/ocsp",
		},
	}

	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	return leafCert, leafKey, issuerCert, issuerKey
}

func buildOCSPResponse(t *testing.T, leaf *x509.Certificate, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, status int, nextUpdate time.Time) []byte {
	respTemplate := ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   nextUpdate,
	}

	respBytes, err := ocsp.CreateResponse(issuer, issuer, respTemplate, issuerKey)
	assert.NoError(t, err)
	return respBytes
}

func TestHandler_Success(t *testing.T) {
	leaf, _, issuer, issuerKey := generateTestCerts(t)

	ocspResp := buildOCSPResponse(t, leaf, issuer, issuerKey, ocsp.Good, time.Now().Add(1*time.Hour))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ocspResp)
	}))
	defer server.Close()

	leaf.OCSPServer = []string{server.URL}

	req := Request{
		CertChain: []string{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(issuer.Raw),
		},
	}

	resp, err := handler(context.Background(), req)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.OCSPResponseBase64)
}


func TestHandler_ExpiredOCSP(t *testing.T) {
	leaf, _, issuer, issuerKey := generateTestCerts(t)

	ocspResp := buildOCSPResponse(t, leaf, issuer, issuerKey, ocsp.Good, time.Now().Add(-1*time.Hour))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ocspResp)
	}))
	defer server.Close()

	leaf.OCSPServer = []string{server.URL}

	req := Request{
		CertChain: []string{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(issuer.Raw),
		},
	}

	_, err := handler(context.Background(), req)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestHandler_SerialMismatch(t *testing.T) {
	leaf, _, issuer, issuerKey := generateTestCerts(t)

	// Different serial
	leaf.SerialNumber = big.NewInt(999)

	ocspResp := buildOCSPResponse(t, leaf, issuer, issuerKey, ocsp.Good, time.Now().Add(1*time.Hour))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ocspResp)
	}))
	defer server.Close()

	leaf.OCSPServer = []string{server.URL}

	req := Request{
		CertChain: []string{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(issuer.Raw),
		},
	}

	_, err := handler(context.Background(), req)
	assert.Error(t, err)
}

func TestHandler_RetryFailure(t *testing.T) {
	leaf, _, issuer, _ := generateTestCerts(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	leaf.OCSPServer = []string{server.URL}

	req := Request{
		CertChain: []string{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(issuer.Raw),
		},
	}

	_, err := handler(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed after retries")
}

func TestHandler_NoOCSPEndpoint(t *testing.T) {
	leaf, _, issuer, _ := generateTestCerts(t)
	leaf.OCSPServer = nil

	req := Request{
		CertChain: []string{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(issuer.Raw),
		},
	}

	_, err := handler(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no OCSP endpoint")
}

func TestHandler_InvalidCertInput(t *testing.T) {
	req := Request{
		CertChain: []string{"invalid-base64"},
	}

	_, err := handler(context.Background(), req)
	assert.Error(t, err)
}
