// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
)

type Request struct {
	CertChain []string `json:"certChain"` // Base64 DER certs, leaf first
}

type Response struct {
	LeafSubject   string `json:"leafSubject"`
	LeafIssuer    string `json:"leafIssuer"`
	SerialNumber  string `json:"serialNumber"`
	OCSPEndpoint  string `json:"ocspEndpoint"`
}

func handler(ctx context.Context, req Request) (Response, error) {
	if len(req.CertChain) == 0 {
		return Response{}, errors.New("certificate chain is empty")
	}

	// Parse certificates
	var certs []*x509.Certificate
	for i, certB64 := range req.CertChain {
		derBytes, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return Response{}, fmt.Errorf("failed to decode cert %d: %w", i, err)
		}

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return Response{}, fmt.Errorf("failed to parse cert %d: %w", i, err)
		}

		certs = append(certs, cert)
	}

	leaf := certs[0]

	// Extract OCSP endpoint
	ocspURL := ""

	// Try leaf first
	if len(leaf.OCSPServer) > 0 {
		ocspURL = leaf.OCSPServer[0]
	} else {
		// Look in intermediates
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

	return Response{
		LeafSubject:  leaf.Subject.String(),
		LeafIssuer:   leaf.Issuer.String(),
		SerialNumber: hex.EncodeToString(leaf.SerialNumber.Bytes()),
		OCSPEndpoint: ocspURL,
	}, nil
}

func main() {
	lambda.Start(handler)
}
