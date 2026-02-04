// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package ocspclient

import (
	"context"
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

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func generateCertChain(t *testing.T, ocspURL string) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey, []string) {
	t.Helper()

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)

	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Leaf",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		OCSPServer: []string{
			ocspURL,
		},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	chain := []string{
		base64.StdEncoding.EncodeToString(leafDER),
		base64.StdEncoding.EncodeToString(issuerDER),
	}

	return leafCert, leafKey, issuerCert, issuerKey, chain
}

func newTestClient(httpClient *http.Client) *Client {
	return New(Config{
		HTTPClient:  httpClient,
		MaxRetries:  1,
		BaseBackoff: 0,
	})
}

func TestFetchStaple_Success(t *testing.T) {

	var leaf *x509.Certificate
	var issuer *x509.Certificate
	var issuerKey *rsa.PrivateKey

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(1 * time.Hour),
		}
		resp, _ := ocsp.CreateResponse(issuer, issuer, template, issuerKey)
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
	defer server.Close()

	leaf, _, issuer, issuerKey, chain := generateCertChain(t, server.URL)

	client := newTestClient(server.Client())

	resp, err := client.FetchStaple(context.Background(), chain)
	require.NoError(t, err)
	require.NotEmpty(t, resp)
}

func TestFetchStaple_Expired(t *testing.T) {

	var leaf *x509.Certificate
	var issuer *x509.Certificate
	var issuerKey *rsa.PrivateKey

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(-1 * time.Hour),
		}
		resp, _ := ocsp.CreateResponse(issuer, issuer, template, issuerKey)
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
	defer server.Close()

	leaf, _, issuer, issuerKey, chain := generateCertChain(t, server.URL)

	client := newTestClient(server.Client())

	_, err := client.FetchStaple(context.Background(), chain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestFetchStaple_SerialMismatch(t *testing.T) {

	var issuer *x509.Certificate
	var issuerKey *rsa.PrivateKey

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		template := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(999),
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(1 * time.Hour),
		}
		resp, _ := ocsp.CreateResponse(issuer, issuer, template, issuerKey)
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
	defer server.Close()

	_, _, issuer, issuerKey, chain := generateCertChain(t, server.URL)

	client := newTestClient(server.Client())

	_, err := client.FetchStaple(context.Background(), chain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "serial mismatch")
}

func TestFetchStaple_RetryFailure(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, _, _, _, chain := generateCertChain(t, server.URL)

	client := New(Config{
		HTTPClient:  server.Client(),
		MaxRetries:  2,
		BaseBackoff: 0,
	})

	_, err := client.FetchStaple(context.Background(), chain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed after retries")
}

func TestFetchStaple_InvalidInput(t *testing.T) {

	client := newTestClient(&http.Client{})

	_, err := client.FetchStaple(context.Background(), []string{"invalid"})
	require.Error(t, err)
}
