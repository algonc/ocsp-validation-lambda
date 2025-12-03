# ---- Build stage ----
FROM golang:1.25 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

 # Build for Lambda (Linux + no CGO)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o bootstrap ./cmd/ocsp-validation-lambda
    
# ---- Runtime stage ----
FROM public.ecr.aws/lambda/provided:al2
    
# Copy binary to Lambda bootstrap location
COPY --from=build /app/bootstrap /var/runtime/bootstrap
    
# Lambda looks for /var/runtime/bootstrap
CMD ["bootstrap"]
    