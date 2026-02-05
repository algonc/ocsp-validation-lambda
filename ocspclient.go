// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package ocspclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type Config struct {
	HTTPClient   *http.Client
	MaxRetries   int
	BaseBackoff  time.Duration
	HTTPTimeout  time.Duration
	Now          func() time.Time
}

type Client struct {
	cfg Config
	httpClient   *http.Client
}

func New(cfg Config) *Client {
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = 500 * time.Millisecond
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 8 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.HTTPTimeout}
	}
	return &Client{cfg: cfg, httpClient: cfg.HTTPClient}
}

func (c *Client) FetchStaple(ctx context.Context, certChainB64 []string) ([]byte, error) {
	if len(certChainB64) < 2 {
		return nil, errors.New("certificate chain must contain at least leaf and issuer")
	}

	certs, err := parseCertificates(certChainB64)
	if err != nil {
		return nil, err
	}

	leaf := certs[0]
	issuer := certs[1]

	ocspURL := findOCSPEndpoint(certs)
	if ocspURL == "" {
		return nil, errors.New("no OCSP endpoint found")
	}

	reqBytes, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("create OCSP request: %w", err)
	}

	respBytes, err := c.executeWithRetry(ctx, ocspURL, reqBytes)
	if err != nil {
		return nil, err
	}

	resp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP response: %w", err)
	}

	if err := c.validate(resp, leaf); err != nil {
		return nil, err
	}

	return respBytes, nil
}

func parseCertificates(chain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(chain))
	for i, b64 := range chain {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode cert %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse cert %d: %w", i, err)
		}
		certs[i] = cert
	}
	return certs, nil
}

func findOCSPEndpoint(certs []*x509.Certificate) string {
	if len(certs[0].OCSPServer) > 0 {
		return certs[0].OCSPServer[0]
	}
	for i := 1; i < len(certs); i++ {
		if len(certs[i].OCSPServer) > 0 {
			return certs[i].OCSPServer[0]
		}
	}
	return ""
}

func (c *Client) executeWithRetry(ctx context.Context, url string, body []byte) ([]byte, error) {

	var lastErr error
	for attempt := 0; attempt < c.cfg.MaxRetries; attempt++ {

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")

		resp, err := c.httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		}

		backoff := c.cfg.BaseBackoff * time.Duration(1<<attempt)
		jitter := time.Duration(rand.Int63n(int64(200 * time.Millisecond)))
		sleep := backoff + jitter

		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("OCSP failed after retries: %w", lastErr)
}

func (c *Client) validate(resp *ocsp.Response, leaf *x509.Certificate) error {
	if resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return errors.New("OCSP serial mismatch")
	}

	if c.cfg.Now().After(resp.NextUpdate) {
		return errors.New("OCSP response expired")
	}

	if resp.Status != ocsp.Good {
		return fmt.Errorf("certificate status: %d", resp.Status)
	}

	return nil
}
