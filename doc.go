// Package gcp_kms_emulator provides a local emulator for the Google Cloud KMS API.
//
// The GCP KMS Emulator is a production-grade implementation providing complete,
// behaviorally-accurate KMS semantics for local development and CI/CD testing.
//
// # Features
//
// Dual protocol support with native gRPC and REST/HTTP APIs for maximum flexibility.
// No GCP credentials or network connectivity required. Real AES-256-GCM encryption
// for deterministic testing behavior. Thread-safe in-memory storage with proper
// synchronization.
//
// # Supported Operations
//
// Key Management: CreateKeyRing, GetKeyRing, ListKeyRings, CreateCryptoKey,
// GetCryptoKey, ListCryptoKeys, UpdateCryptoKey
//
// Key Versioning: CreateCryptoKeyVersion, GetCryptoKeyVersion, ListCryptoKeyVersions,
// UpdateCryptoKeyPrimaryVersion, UpdateCryptoKeyVersion, DestroyCryptoKeyVersion
//
// Encryption: Encrypt (AES-256-GCM), Decrypt (works with any enabled version)
//
// Version State Transitions: PENDING_GENERATION → ENABLED → DISABLED →
// DESTROY_SCHEDULED → DESTROYED, with bidirectional ENABLED ↔ DISABLED transitions.
//
// # Usage
//
// Start the gRPC server:
//
//	import "github.com/blackwell-systems/gcp-kms-emulator/cmd/server"
//	// See cmd/server/main.go for server implementation
//
// Use with GCP SDK:
//
//	import (
//	    kms "cloud.google.com/go/kms/apiv1"
//	    "google.golang.org/grpc"
//	    "google.golang.org/grpc/credentials/insecure"
//	)
//
//	conn, _ := grpc.NewClient(
//	    "localhost:9090",
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	)
//	client, _ := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
//
// # Server Variants
//
// Three server variants are available:
//   - server: gRPC only (fastest startup, SDK users)
//   - server-rest: REST/HTTP only (curl, scripts, any language)
//   - server-dual: Both gRPC and REST (maximum flexibility)
//
// # Docker
//
// Pre-built multi-architecture Docker images (linux/amd64, linux/arm64):
//
//	docker run -p 9090:9090 ghcr.io/blackwell-systems/gcp-kms-emulator:latest
//	docker run -p 8080:8080 ghcr.io/blackwell-systems/gcp-kms-emulator:rest
//	docker run -p 9090:9090 -p 8080:8080 ghcr.io/blackwell-systems/gcp-kms-emulator:dual
//
// # Use Cases
//
// Local development testing of KMS encryption without cloud access. CI/CD pipeline
// integration tests without GCP credentials. Unit testing with deterministic
// encryption behavior. Security testing to validate encryption workflows.
// Cost reduction by avoiding GCP API charges during development.
//
// # Coverage
//
// Currently implements 14 of ~26 KMS methods (54% coverage), focused on complete
// key management and lifecycle operations. Does not implement asymmetric operations,
// MAC operations, key import/export, or raw encryption operations.
//
// # Architecture
//
// Thread-safe in-memory storage with sync.RWMutex for concurrent operations.
// Real AES-256-GCM encryption (not mocked) for authentic behavior. Custom HTTP
// gateway for REST API (not grpc-gateway) with GCP-compatible endpoints.
// Three server variants built from same codebase using build tags.
//
// # License
//
// Apache 2.0 - See LICENSE file for details.
//
// # Links
//
// Repository: https://github.com/blackwell-systems/gcp-kms-emulator
// Documentation: https://pkg.go.dev/github.com/blackwell-systems/gcp-kms-emulator
// Issues: https://github.com/blackwell-systems/gcp-kms-emulator/issues
package main
