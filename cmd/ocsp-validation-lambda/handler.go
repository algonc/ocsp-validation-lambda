// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/crypto/ocsp"
)

type Request struct {
	CertChain []string `json:"certChain"` // Base64 DER certs, leaf first
}

type Response struct {
	OCSPResponseBase64 string `json:"ocspResponseBase64"`
}

func handler(ctx context.Context, req Request) (Response, error) {
	if len(req.CertChain) < 2 {
		return Response{}, errors.New("certificate chain must include at least leaf and issuer")
	}

	// -------------------------
	// Parse Certificates
	// -------------------------
	certs := make([]*x509.Certificate, len(req.CertChain))

	for i, certB64 := range req.CertChain {
		derBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return Response{}, fmt.Errorf("failed to decode cert %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return Response{}, fmt.Errorf("failed to parse cert %d: %w", i, err)
		}

		certs[i] = cert
	}

	leaf := certs[0]
	issuer := certs[1] // OCSP must use direct issuer

	// -------------------------
	// Locate OCSP Endpoint
	// -------------------------
	ocspURL := ""

	if len(leaf.OCSPServer) > 0 {
		ocspURL = leaf.OCSPServer[0]
	} else {
		for i := 1; i < len(certs); i++ {
			if len(certs[i].OCSPServer) > 0 {
				ocspURL = certs[i].OCSPServer[0]
				break
			}
		}
	}

	if ocspURL == "" {
		return Response{}, errors.New("no OCSP endpoint found in certificate chain")
	}

	log.Printf("Using OCSP endpoint: %s", ocspURL)

	// -------------------------
	// Build OCSP Request
	// -------------------------
	ocspReqBytes, err := ocsp.CreateRequest(
		leaf,
		issuer,
		&ocsp.RequestOptions{
			Hash: crypto.SHA1, // SHA1 is required by many OCSP responders
		},
	)
	if err != nil {
		return Response{}, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	log.Printf("OCSP request created (len=%d)", len(ocspReqBytes))

	// -------------------------
	// Execute HTTP Request
	// -------------------------
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(ocspReqBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to execute OCSP HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("OCSP responder returned status %d", httpResp.StatusCode)
	}

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	log.Printf("OCSP response received (len=%d)", len(respBytes))

	// -------------------------
	// Parse + Inspect OCSP Response
	// -------------------------
	ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return Response{}, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	log.Printf("OCSP Response Status: %s", ocspStatusToString(ocspResp.Status))
	log.Printf("This Update: %s", ocspResp.ThisUpdate)
	log.Printf("Next Update: %s", ocspResp.NextUpdate)
	log.Printf("Produced At: %s", ocspResp.ProducedAt)

	if ocspResp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return Response{}, errors.New("OCSP response serial number mismatch")
	}

	// -------------------------
	// Return Base64 OCSP Response (for stapling)
	// -------------------------
	ocspRespBase64 := base64.StdEncoding.EncodeToString(respBytes)

	return Response{
		OCSPResponseBase64: ocspRespBase64,
	}, nil
}

func ocspStatusToString(status int) string {
	switch status {
	case ocsp.Good:
		return "GOOD"
	case ocsp.Revoked:
		return "REVOKED"
	case ocsp.Unknown:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("UNDEFINED (%d)", status)
	}
}

func main() {
	lambda.Start(handler)
}
