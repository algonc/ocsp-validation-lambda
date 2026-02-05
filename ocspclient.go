// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package ocspclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	HTTPClient  httpClient
	MaxRetries  int
	BaseBackoff time.Duration
	HTTPTimeout time.Duration
	Now         func() time.Time
}

type Client struct {
	cfg        Config
	httpClient httpClient
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

type FetchOption func(*fetchConfig) error

type fetchConfig struct {
	base64Certs []string
	pemPaths    []string
}

func WithBase64Certs(certs []string) FetchOption {
	return func(fc *fetchConfig) error {
		if len(certs) == 0 {
			return errors.New("no base64 certs provided")
		}
		fc.base64Certs = certs
		return nil
	}
}

func WithPEMPaths(paths []string) FetchOption {
	return func(fc *fetchConfig) error {
		if len(paths) == 0 {
			return errors.New("no PEM paths provided")
		}
		fc.pemPaths = paths
		return nil
	}
}

func (c *Client) FetchStaple(ctx context.Context, opts ...FetchOption) ([]byte, error) {
	if len(opts) == 0 {
		return nil, errors.New("no fetch options provided")
	}

	cfg := &fetchConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	var certChainB64 []string
	var err error

	if len(cfg.base64Certs) > 0 {
		certChainB64 = cfg.base64Certs
	} else if len(cfg.pemPaths) > 0 {
		certChainB64, err = pemPathsToBase64(cfg.pemPaths)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("no certificates provided in options")
	}

	return c.fetchStapleFromBase64(ctx, certChainB64)
}

func pemPathsToBase64(paths []string) ([]string, error) {
	var certs []*x509.Certificate

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read PEM %s: %w", path, err)
		}

		remaining := data
		for len(remaining) > 0 {
			var block *pem.Block
			block, remaining = pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate in %s: %w", path, err)
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) < 2 {
		return nil, errors.New("need at least leaf and issuer certificates")
	}

	chainB64 := make([]string, len(certs))
	for i, cert := range certs {
		chainB64[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return chainB64, nil
}

func (c *Client) fetchStapleFromBase64(ctx context.Context, certChainB64 []string) ([]byte, error) {
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
