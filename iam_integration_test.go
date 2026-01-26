package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
)

// TestIAMIntegration tests IAM permission checks with different modes
// These tests require the IAM emulator to be running
func TestIAMIntegration(t *testing.T) {
	// Check if IAM emulator is available
	iamHost := os.Getenv("IAM_HOST")
	if iamHost == "" {
		t.Skip("Skipping IAM integration tests - IAM_HOST not set")
	}

	tests := []struct {
		name         string
		iamMode      string
		principal    string
		operation    func(kmspb.KeyManagementServiceClient, context.Context) error
		expectError  bool
		expectedCode codes.Code
	}{
		{
			name:      "permissive mode - allow without principal",
			iamMode:   "permissive",
			principal: "",
			operation: func(client kmspb.KeyManagementServiceClient, ctx context.Context) error {
				_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
					Parent:    "projects/test/locations/global",
					KeyRingId: "test-ring-1",
				})
				return err
			},
			expectError: false,
		},
		{
			name:      "strict mode - deny without principal",
			iamMode:   "strict",
			principal: "",
			operation: func(client kmspb.KeyManagementServiceClient, ctx context.Context) error {
				_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
					Parent:    "projects/test/locations/global",
					KeyRingId: "test-ring-2",
				})
				return err
			},
			expectError:  true,
			expectedCode: codes.PermissionDenied,
		},
		{
			name:      "strict mode - allow with authorized principal",
			iamMode:   "strict",
			principal: "user:admin@example.com",
			operation: func(client kmspb.KeyManagementServiceClient, ctx context.Context) error {
				_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
					Parent:    "projects/test/locations/global",
					KeyRingId: "test-ring-3",
				})
				return err
			},
			expectError: false,
		},
		{
			name:      "strict mode - deny unauthorized principal",
			iamMode:   "strict",
			principal: "user:unauthorized@example.com",
			operation: func(client kmspb.KeyManagementServiceClient, ctx context.Context) error {
				_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
					Parent:    "projects/test/locations/global",
					KeyRingId: "test-ring-4",
				})
				return err
			},
			expectError:  true,
			expectedCode: codes.PermissionDenied,
		},
		{
			name:      "strict mode - encrypt requires permission",
			iamMode:   "strict",
			principal: "user:admin@example.com",
			operation: func(client kmspb.KeyManagementServiceClient, ctx context.Context) error {
				// First create keyring and key
				_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
					Parent:    "projects/test/locations/global",
					KeyRingId: "test-ring-5",
				})
				if err != nil {
					return fmt.Errorf("setup failed: %w", err)
				}

				_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
					Parent:      "projects/test/locations/global/keyRings/test-ring-5",
					CryptoKeyId: "test-key",
					CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
				})
				if err != nil {
					return fmt.Errorf("setup failed: %w", err)
				}

				// Try to encrypt
				_, err = client.Encrypt(ctx, &kmspb.EncryptRequest{
					Name:      "projects/test/locations/global/keyRings/test-ring-5/cryptoKeys/test-key",
					Plaintext: []byte("test"),
				})
				return err
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set IAM mode for this test
			os.Setenv("IAM_MODE", tt.iamMode)
			defer os.Unsetenv("IAM_MODE")

			// Create test server
			_, lis, cleanup := setupTestServerForIAM(t)
			defer cleanup()

			conn, cleanupClient := setupTestClient(t, lis)
			defer cleanupClient()

			client := kmspb.NewKeyManagementServiceClient(conn)

			// Create context with principal if specified
			ctx := context.Background()
			if tt.principal != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "x-emulator-principal", tt.principal)
			}

			// Run operation
			err := tt.operation(client, ctx)

			// Check result
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}

				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("Expected gRPC status error, got: %v", err)
					return
				}

				if st.Code() != tt.expectedCode {
					t.Errorf("Expected code %v, got %v", tt.expectedCode, st.Code())
				}
			} else {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
			}
		})
	}
}

// TestIAMModeOff verifies that IAM_MODE=off works as before (no permission checks)
func TestIAMModeOff(t *testing.T) {
	os.Setenv("IAM_MODE", "off")
	defer os.Unsetenv("IAM_MODE")

	_, lis, cleanup := setupTestServerForIAM(t)
	defer cleanup()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Should succeed without principal when IAM is off
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/global",
		KeyRingId: "test-ring-off",
	})

	if err != nil {
		t.Errorf("Expected success with IAM_MODE=off, got error: %v", err)
	}
}

// TestIAMPermissiveVsStrict verifies the difference between permissive and strict modes
func TestIAMPermissiveVsStrict(t *testing.T) {
	iamHost := os.Getenv("IAM_HOST")
	if iamHost == "" {
		t.Skip("Skipping IAM integration tests - IAM_HOST not set")
	}

	tests := []struct {
		name         string
		iamMode      string
		expectError  bool
		expectedCode codes.Code
	}{
		{
			name:        "permissive mode - fail open on connectivity error",
			iamMode:     "permissive",
			expectError: false,
		},
		{
			name:         "strict mode - fail closed on connectivity error",
			iamMode:      "strict",
			expectError:  true,
			expectedCode: codes.Internal, // or PermissionDenied depending on error type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set IAM mode
			os.Setenv("IAM_MODE", tt.iamMode)
			defer os.Unsetenv("IAM_MODE")

			// Point to non-existent IAM host to simulate connectivity error
			originalHost := os.Getenv("IAM_HOST")
			os.Setenv("IAM_HOST", "localhost:65535") // unlikely to be listening
			defer os.Setenv("IAM_HOST", originalHost)

			// Create test server (will fail to connect to IAM but continue in permissive mode)
			_, lis, cleanup := setupTestServerForIAM(t)
			defer cleanup()

			conn, cleanupClient := setupTestClient(t, lis)
			defer cleanupClient()

			client := kmspb.NewKeyManagementServiceClient(conn)
			ctx := context.Background()

			_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
				Parent:    "projects/test/locations/global",
				KeyRingId: "test-ring",
			})

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error in %s mode, got nil", tt.iamMode)
				}
			} else {
				if err != nil {
					t.Errorf("Expected success in %s mode (fail-open), got error: %v", tt.iamMode, err)
				}
			}
		})
	}
}

// setupTestServerForIAM creates a test server with IAM integration enabled
func setupTestServerForIAM(t *testing.T) (*grpc.Server, *bufconn.Listener, func()) {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)

	grpcServer := grpc.NewServer()
	kmsServer, err := server.NewServer()
	if err != nil {
		t.Fatalf("Failed to create KMS server: %v", err)
	}
	kmspb.RegisterKeyManagementServiceServer(grpcServer, kmsServer)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("Server exited: %v", err)
		}
	}()

	cleanup := func() {
		grpcServer.Stop()
		lis.Close()
	}

	return grpcServer, lis, cleanup
}
