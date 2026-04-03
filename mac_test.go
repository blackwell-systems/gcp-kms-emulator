package gcp_kms_emulator_test

import (
	"context"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIntegration_MacSignVerify(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "mac-keyring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	// Create MAC key with HMAC_SHA256
	macKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "projects/test-project/locations/global/keyRings/mac-keyring",
		CryptoKeyId: "mac-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey (MAC) failed: %v", err)
	}

	versionName := macKey.Primary.Name
	data := []byte("hello, MAC test!")

	// MacSign
	signResp, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: versionName,
		Data: data,
	})
	if err != nil {
		t.Fatalf("MacSign failed: %v", err)
	}
	if len(signResp.Mac) == 0 {
		t.Fatal("MacSign returned empty mac")
	}
	if signResp.Name != versionName {
		t.Errorf("MacSign response name = %q, want %q", signResp.Name, versionName)
	}

	// MacVerify with correct data -> true
	verifyResp, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: versionName,
		Data: data,
		Mac:  signResp.Mac,
	})
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !verifyResp.Success {
		t.Error("MacVerify should return success=true for matching data")
	}

	// MacVerify with wrong data -> false
	verifyResp, err = client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: versionName,
		Data: []byte("wrong data"),
		Mac:  signResp.Mac,
	})
	if err != nil {
		t.Fatalf("MacVerify with wrong data should not error: %v", err)
	}
	if verifyResp.Success {
		t.Error("MacVerify should return success=false for mismatched data")
	}
}

func TestIntegration_MacSignWrongPurpose(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "mac-wrong-keyring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	// Create ENCRYPT_DECRYPT key (not MAC)
	encKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "projects/test-project/locations/global/keyRings/mac-wrong-keyring",
		CryptoKeyId: "enc-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey (ENCRYPT_DECRYPT) failed: %v", err)
	}

	// Attempt MacSign with encryption key -> should fail
	_, err = client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: encKey.Primary.Name,
		Data: []byte("should fail"),
	})
	if err == nil {
		t.Fatal("MacSign with ENCRYPT_DECRYPT key should fail")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}
