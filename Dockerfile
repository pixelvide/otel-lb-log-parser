# Multi-stage build for Go Lambda
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the Lambda function
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bootstrap cmd/lambda/main.go

# Final stage - use AWS Lambda base image
FROM public.ecr.aws/lambda/provided:al2023

# Copy the binary from builder
COPY --from=builder /build/bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap

# Set the CMD to your handler
CMD [ "bootstrap" ]
