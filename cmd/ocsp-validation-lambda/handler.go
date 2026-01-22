// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/crypto/ocsp"
)

type Request struct {
	CertChain []string `json:"certChain"`
}

type Response struct {
	OCSPResponseBase64 string `json:"ocspResponseBase64"`
}

const (
	maxRetries        = 3
	baseBackoff       = 500 * time.Millisecond
	httpTimeout       = 8 * time.Second
	metricsNamespace  = "OCSPService"
)

func handler(ctx context.Context, req Request) (Response, error) {
	start := time.Now()

	if len(req.CertChain) < 2 {
		recordMetric("InvalidInput", 1)
		return Response{}, errors.New("certificate chain must contain at least leaf and issuer")
	}

	// ---------------- Parse Certificates ----------------
	certs, err := parseCertificates(req.CertChain)
	if err != nil {
		recordMetric("ParseError", 1)
		return Response{}, err
	}

	leaf := certs[0]
	issuer := certs[1]

	// ---------------- Locate OCSP Endpoint ----------------
	ocspURL := findOCSPEndpoint(certs)
	if ocspURL == "" {
		recordMetric("NoEndpoint", 1)
		return Response{}, errors.New("no OCSP endpoint found")
	}

	logJSON("OCSP endpoint selected", map[string]any{
		"url": ocspURL,
	})

	// ---------------- Build OCSP Request ----------------
	ocspReq, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA1,
	})
	if err != nil {
		recordMetric("RequestBuildError", 1)
		return Response{}, fmt.Errorf("failed to build OCSP request: %w", err)
	}

	// ---------------- Execute with Retry ----------------
	respBytes, err := executeWithRetry(ctx, ocspURL, ocspReq)
	if err != nil {
		recordMetric("RequestFailure", 1)
		return Response{}, err
	}

	// ---------------- Parse + Validate Response ----------------
	ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		recordMetric("ParseResponseError", 1)
		return Response{}, fmt.Errorf("invalid OCSP response: %w", err)
	}

	if err := validateOCSPResponse(ocspResp, leaf); err != nil {
		recordMetric("ValidationError", 1)
		return Response{}, err
	}

	logJSON("OCSP validated", map[string]any{
		"status":      statusToString(ocspResp.Status),
		"thisUpdate":  ocspResp.ThisUpdate,
		"nextUpdate":  ocspResp.NextUpdate,
		"producedAt":  ocspResp.ProducedAt,
	})

	recordMetric("Success", 1)
	recordMetric("LatencyMs", float64(time.Since(start).Milliseconds()))

	return Response{
		OCSPResponseBase64: base64.StdEncoding.EncodeToString(respBytes),
	}, nil
}

func parseCertificates(chain []string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(chain))
	for i, b64 := range chain {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode error cert %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse error cert %d: %w", i, err)
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

func executeWithRetry(ctx context.Context, url string, body []byte) ([]byte, error) {
	client := &http.Client{Timeout: httpTimeout}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return io.ReadAll(resp.Body)
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		backoff := baseBackoff * time.Duration(1<<attempt)
		jitter := time.Duration(rand.Int63n(int64(200 * time.Millisecond)))
		sleep := backoff + jitter

		logJSON("OCSP retry", map[string]any{
			"attempt": attempt + 1,
			"error":   lastErr.Error(),
			"sleepMs": sleep.Milliseconds(),
		})

		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("OCSP request failed after retries: %w", lastErr)
}

func validateOCSPResponse(resp *ocsp.Response, leaf *x509.Certificate) error {
	if resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return errors.New("OCSP serial mismatch")
	}

	if time.Now().After(resp.NextUpdate) {
		return errors.New("OCSP response expired")
	}

	if resp.Status != ocsp.Good {
		return fmt.Errorf("certificate status is %s", statusToString(resp.Status))
	}

	return nil
}

func statusToString(status int) string {
	switch status {
	case ocsp.Good:
		return "GOOD"
	case ocsp.Revoked:
		return "REVOKED"
	case ocsp.Unknown:
		return "UNKNOWN"
	default:
		return "UNDEFINED"
	}
}

func logJSON(msg string, fields map[string]any) {
	entry := map[string]any{
		"message": msg,
		"service": "ocsp-lambda",
	}
	for k, v := range fields {
		entry[k] = v
	}
	j, _ := json.Marshal(entry)
	log.Println(string(j))
}

func recordMetric(name string, value float64) {
	emf := map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []map[string]any{
				{
					"Namespace": metricsNamespace,
					"Dimensions": [][]string{
						{"Service"},
					},
					"Metrics": []map[string]string{
						{"Name": name},
					},
				},
			},
		},
		"Service": name,
		name:      value,
	}
	b, _ := json.Marshal(emf)
	fmt.Fprintln(os.Stdout, string(b))
}

func main() {
	lambda.Start(handler)
}
