# Dockerfile for GCP KMS Emulator
# Multi-stage build with variant selection via build args
#
# Build variants:
#   docker build --build-arg VARIANT=grpc -t kms-emulator:grpc .      # gRPC only (default)
#   docker build --build-arg VARIANT=rest -t kms-emulator:rest .      # REST only
#   docker build --build-arg VARIANT=dual -t kms-emulator:dual .      # Both protocols

# Build stage
FROM golang:alpine AS builder

ARG VARIANT=grpc

WORKDIR /build

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the appropriate server binary based on variant
RUN case "${VARIANT}" in \
    grpc) \
        echo "Building gRPC-only server..." && \
        CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server \
        ;; \
    rest) \
        echo "Building REST-only server..." && \
        CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server-rest \
        ;; \
    dual) \
        echo "Building dual-protocol server..." && \
        CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server-dual \
        ;; \
    *) \
        echo "Invalid VARIANT: ${VARIANT}. Must be grpc, rest, or dual" && exit 1 \
        ;; \
    esac

# Final stage - minimal image
FROM alpine:latest

ARG VARIANT=grpc

# Install ca-certificates
RUN apk --no-cache add --no-scripts ca-certificates && \
    update-ca-certificates || true

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/server .

# Expose ports (gRPC: 9090, HTTP: 8080)
EXPOSE 9090
EXPOSE 8080

# Run as non-root user for security
RUN addgroup -g 1000 kmsmock && \
    adduser -D -u 1000 -G kmsmock kmsmock && \
    chown -R kmsmock:kmsmock /app

USER kmsmock

# Set default environment variables
ENV GCP_KMS_LOG_LEVEL=info

# Label the image with build variant
LABEL org.opencontainers.image.title="GCP KMS Emulator (${VARIANT})"
LABEL org.opencontainers.image.description="Local implementation of GCP KMS API"
LABEL org.opencontainers.image.variant="${VARIANT}"

ENTRYPOINT ["/app/server"]
