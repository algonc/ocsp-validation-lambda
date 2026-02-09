// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log"

	"github.com/algonc/ocspclient"
	"github.com/aws/aws-lambda-go/lambda"
)

// Request expects a chain of base64-encoded DER certificates (leaf first)
type Request struct {
	Base64CertChain []string `json:"base64CertChain"`
}

type Response struct {
	OCSPResponseBase64 string `json:"ocspResponseBase64"`
}

// OCSPFetcher interface keeps the handler testable
type OCSPFetcher interface {
	FetchStaple(ctx context.Context, opts ...ocspclient.FetchOption) ([]byte, error)
}

// Initialize client once
var client OCSPFetcher = ocspclient.New(ocspclient.Config{})

func handler(ctx context.Context, req Request) (Response, error) {
	if len(req.Base64CertChain) < 2 {
		return Response{}, errors.New("certificate chain must contain at least leaf and issuer")
	}

	respBytes, err := client.FetchStaple(ctx, ocspclient.WithBase64Certs(req.Base64CertChain))
	if err != nil {
		log.Printf("OCSP error: %v", err)
		return Response{}, err
	}

	return Response{
		OCSPResponseBase64: base64.StdEncoding.EncodeToString(respBytes),
	}, nil
}

func main() {
	lambda.Start(handler)
}
