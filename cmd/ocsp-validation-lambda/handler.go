// Copyright (c) 2025 André Gonçalves. All rights reserved.
// Use of this source code is governed by the MIT License that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/algonc/ocsp-validation-lambda/pkg/ocspclient"
)

type Request struct {
	CertChain []string `json:"certChain"`
}

type Response struct {
	OCSPResponseBase64 string `json:"ocspResponseBase64"`
}

type OCSPFetcher interface {
	FetchStaple(ctx context.Context, certChainB64 []string) ([]byte, error)
}

var client OCSPFetcher = ocspclient.New(ocspclient.Config{})

func handler(ctx context.Context, req Request) (Response, error) {

	respBytes, err := client.FetchStaple(ctx, req.CertChain)
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
