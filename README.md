# ocspclient

`ocspclient` is a Go package that provides functionality to fetch OCSP staples for X.509 certificates. It supports fetching OCSP responses from:

* Base64-encoded DER certificate chains
* PEM certificate files containing one or more certificates

The package includes retry logic with exponential backoff and can be integrated into both CLI tools and applications.

---

## Features

* Fetch OCSP staples for leaf certificates given a certificate chain
* Accepts input as base64-encoded DER or PEM files
* Automatic detection of OCSP endpoints from certificates
* Retries with exponential backoff for transient network errors
* Validates OCSP response integrity and expiration

---

## Installation

```bash
go get github.com/algonc/ocspclient
```

---

## Usage

### Basic Example with Base64 Certificates

```go
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/algonc/ocspclient"
)

func main() {
	leafB64 := "BASE64_ENCODED_LEAF_CERT"
	issuerB64 := "BASE64_ENCODED_ISSUER_CERT"

	client := ocspclient.New(ocspclient.Config{})

	ocspResp, err := client.FetchStaple(context.Background(),
		ocspclient.WithBase64Certs([]string{leafB64, issuerB64}),
	)
	if err != nil {
		log.Fatalf("OCSP fetch failed: %v", err)
	}

	fmt.Printf("OCSP response (base64): %s\n", base64.StdEncoding.EncodeToString(ocspResp))
}
```

---

### Example Using PEM Files

```go
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/algonc/ocspclient"
)

func main() {
	pemFiles := []string{"./certs/leaf.pem", "./certs/issuer.pem"}

	client := ocspclient.New(ocspclient.Config{})

	ocspResp, err := client.FetchStaple(context.Background(),
		ocspclient.WithPEMPaths(pemFiles),
	)
	if err != nil {
		log.Fatalf("OCSP fetch failed: %v", err)
	}

	fmt.Printf("OCSP response (base64): %s\n", base64.StdEncoding.EncodeToString(ocspResp))
}
```

---

## Configuration

The `Config` struct allows customizing the client:

```go
type Config struct {
	HTTPClient  httpClient      // Custom HTTP client (default uses http.Client with timeout)
	MaxRetries  int             // Maximum number of retry attempts (default 3)
	BaseBackoff time.Duration   // Base backoff duration for retries (default 500ms)
	HTTPTimeout time.Duration   // Timeout for HTTP requests (default 8s)
}
```

---

## Error Handling

* `no OCSP endpoint found` – returned when neither leaf nor intermediate certificates contain an OCSP URL.
* `OCSP response expired` – returned if the `NextUpdate` timestamp is in the past.
* `OCSP serial mismatch` – returned if the OCSP response serial number does not match the leaf certificate.
* Network errors and HTTP errors are wrapped with retry information.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
