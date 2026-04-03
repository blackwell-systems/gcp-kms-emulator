package gcp_kms_emulator_test

import (
	"bytes"
	"context"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIntegration_RawEncryptDecrypt(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create a keyring
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "raw-test-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	// Create a RAW_ENCRYPT_DECRYPT key with AES_256_GCM algorithm
	keyResp, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "projects/test-project/locations/global/keyRings/raw-test-ring",
		CryptoKeyId: "raw-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	versionName := keyResp.Primary.Name
	plaintext := []byte("hello, raw encrypt/decrypt!")
	aad := []byte("additional authenticated data")

	// RawEncrypt
	encResp, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                         versionName,
		Plaintext:                    plaintext,
		AdditionalAuthenticatedData:  aad,
	})
	if err != nil {
		t.Fatalf("RawEncrypt failed: %v", err)
	}

	if len(encResp.Ciphertext) == 0 {
		t.Fatal("RawEncrypt returned empty ciphertext")
	}
	if len(encResp.InitializationVector) == 0 {
		t.Fatal("RawEncrypt returned empty initialization vector")
	}
	if encResp.TagLength <= 0 {
		t.Fatalf("RawEncrypt returned invalid tag length: %d", encResp.TagLength)
	}

	// RawDecrypt
	decResp, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                         versionName,
		Ciphertext:                   encResp.Ciphertext,
		InitializationVector:         encResp.InitializationVector,
		AdditionalAuthenticatedData:  aad,
	})
	if err != nil {
		t.Fatalf("RawDecrypt failed: %v", err)
	}

	if !bytes.Equal(decResp.Plaintext, plaintext) {
		t.Fatalf("Roundtrip failed: got %q, want %q", decResp.Plaintext, plaintext)
	}
}

func TestIntegration_RawDecryptWrongAAD(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring and key
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "raw-aad-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	keyResp, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "projects/test-project/locations/global/keyRings/raw-aad-ring",
		CryptoKeyId: "raw-aad-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	versionName := keyResp.Primary.Name

	// Encrypt with AAD "foo"
	encResp, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                         versionName,
		Plaintext:                    []byte("secret"),
		AdditionalAuthenticatedData:  []byte("foo"),
	})
	if err != nil {
		t.Fatalf("RawEncrypt failed: %v", err)
	}

	// Decrypt with AAD "bar" -- should fail
	_, err = client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                         versionName,
		Ciphertext:                   encResp.Ciphertext,
		InitializationVector:         encResp.InitializationVector,
		AdditionalAuthenticatedData:  []byte("bar"),
	})
	if err == nil {
		t.Fatal("Expected error when decrypting with wrong AAD, got nil")
	}
}

func TestIntegration_GenerateRandomBytes(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Valid request: 32 bytes
	resp, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:    "projects/test-project/locations/global",
		LengthBytes: 32,
	})
	if err != nil {
		t.Fatalf("GenerateRandomBytes(32) failed: %v", err)
	}
	if len(resp.Data) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(resp.Data))
	}

	// Invalid request: 0 bytes -> error
	_, err = client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:    "projects/test-project/locations/global",
		LengthBytes: 0,
	})
	if err == nil {
		t.Fatal("Expected error for length=0, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("Expected InvalidArgument error, got %v", err)
	}
}
