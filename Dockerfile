# Multi-stage build for Go Lambda
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the Lambda function
# Use TARGETARCH to support multi-arch builds (amd64/arm64)
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o bootstrap ./cmd/lambda

# Final stage - use AWS Lambda base image
FROM public.ecr.aws/lambda/provided:al2023

# Copy the binary from builder
COPY --from=builder /build/bootstrap ${LAMBDA_RUNTIME_DIR}/bootstrap

# Set the CMD to your handler
CMD [ "bootstrap" ]
