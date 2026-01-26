package main

import (
	"context"
	"net"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
)

func setupTestServer(t *testing.T) (*grpc.Server, *bufconn.Listener, func()) {
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

func setupTestClient(t *testing.T, lis *bufconn.Listener) (*grpc.ClientConn, func()) {
	t.Helper()

	ctx := context.Background()
	//nolint:staticcheck // DialContext required for bufconn in tests
	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to create gRPC connection: %v", err)
	}

	cleanup := func() {
		conn.Close()
	}

	return conn, cleanup
}

func TestIntegration_FullWorkflow(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	t.Run("CreateKeyRing", func(t *testing.T) {
		req := &kmspb.CreateKeyRingRequest{
			Parent:    "projects/test-project/locations/global",
			KeyRingId: "test-keyring",
		}

		resp, err := client.CreateKeyRing(ctx, req)
		if err != nil {
			t.Fatalf("CreateKeyRing failed: %v", err)
		}

		if resp.Name != "projects/test-project/locations/global/keyRings/test-keyring" {
			t.Errorf("Unexpected keyring name: %s", resp.Name)
		}
	})

	t.Run("GetKeyRing", func(t *testing.T) {
		req := &kmspb.GetKeyRingRequest{
			Name: "projects/test-project/locations/global/keyRings/test-keyring",
		}

		resp, err := client.GetKeyRing(ctx, req)
		if err != nil {
			t.Fatalf("GetKeyRing failed: %v", err)
		}

		if resp.Name != "projects/test-project/locations/global/keyRings/test-keyring" {
			t.Errorf("Unexpected keyring name: %s", resp.Name)
		}
	})

	t.Run("ListKeyRings", func(t *testing.T) {
		req := &kmspb.ListKeyRingsRequest{
			Parent: "projects/test-project/locations/global",
		}

		resp, err := client.ListKeyRings(ctx, req)
		if err != nil {
			t.Fatalf("ListKeyRings failed: %v", err)
		}

		if len(resp.KeyRings) != 1 {
			t.Errorf("Expected 1 keyring, got %d", len(resp.KeyRings))
		}
	})

	t.Run("CreateCryptoKey", func(t *testing.T) {
		req := &kmspb.CreateCryptoKeyRequest{
			Parent:      "projects/test-project/locations/global/keyRings/test-keyring",
			CryptoKeyId: "test-key",
			CryptoKey: &kmspb.CryptoKey{
				Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			},
		}

		resp, err := client.CreateCryptoKey(ctx, req)
		if err != nil {
			t.Fatalf("CreateCryptoKey failed: %v", err)
		}

		if resp.Name != "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key" {
			t.Errorf("Unexpected crypto key name: %s", resp.Name)
		}

		if resp.Primary == nil {
			t.Error("Primary version should not be nil")
		}

		if resp.Primary.Name != "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1" {
			t.Errorf("Unexpected primary version name: %s", resp.Primary.Name)
		}
	})

	t.Run("GetCryptoKey", func(t *testing.T) {
		req := &kmspb.GetCryptoKeyRequest{
			Name: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
		}

		resp, err := client.GetCryptoKey(ctx, req)
		if err != nil {
			t.Fatalf("GetCryptoKey failed: %v", err)
		}

		if resp.Name != "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key" {
			t.Errorf("Unexpected crypto key name: %s", resp.Name)
		}
	})

	t.Run("ListCryptoKeys", func(t *testing.T) {
		req := &kmspb.ListCryptoKeysRequest{
			Parent: "projects/test-project/locations/global/keyRings/test-keyring",
		}

		resp, err := client.ListCryptoKeys(ctx, req)
		if err != nil {
			t.Fatalf("ListCryptoKeys failed: %v", err)
		}

		if len(resp.CryptoKeys) != 1 {
			t.Errorf("Expected 1 crypto key, got %d", len(resp.CryptoKeys))
		}
	})

	var ciphertext []byte

	t.Run("Encrypt", func(t *testing.T) {
		plaintext := []byte("Hello, Integration Test!")
		req := &kmspb.EncryptRequest{
			Name:      "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			Plaintext: plaintext,
		}

		resp, err := client.Encrypt(ctx, req)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if len(resp.Ciphertext) == 0 {
			t.Error("Ciphertext should not be empty")
		}

		ciphertext = resp.Ciphertext
	})

	t.Run("Decrypt", func(t *testing.T) {
		req := &kmspb.DecryptRequest{
			Name:       "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			Ciphertext: ciphertext,
		}

		resp, err := client.Decrypt(ctx, req)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		expected := "Hello, Integration Test!"
		if string(resp.Plaintext) != expected {
			t.Errorf("Expected plaintext '%s', got '%s'", expected, string(resp.Plaintext))
		}
	})

	t.Run("CreateCryptoKeyVersion", func(t *testing.T) {
		req := &kmspb.CreateCryptoKeyVersionRequest{
			Parent: "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
		}

		resp, err := client.CreateCryptoKeyVersion(ctx, req)
		if err != nil {
			t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
		}

		if resp.Name != "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/2" {
			t.Errorf("Expected version 2, got %s", resp.Name)
		}

		if resp.State != kmspb.CryptoKeyVersion_ENABLED {
			t.Errorf("Expected state ENABLED, got %v", resp.State)
		}
	})

	t.Run("UpdateCryptoKeyPrimaryVersion", func(t *testing.T) {
		req := &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name:               "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			CryptoKeyVersionId: "2",
		}

		resp, err := client.UpdateCryptoKeyPrimaryVersion(ctx, req)
		if err != nil {
			t.Fatalf("UpdateCryptoKeyPrimaryVersion failed: %v", err)
		}

		if resp.Primary.Name != "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/2" {
			t.Errorf("Expected primary version 2, got %s", resp.Primary.Name)
		}
	})

	t.Run("DecryptOldCiphertext", func(t *testing.T) {
		req := &kmspb.DecryptRequest{
			Name:       "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			Ciphertext: ciphertext,
		}

		resp, err := client.Decrypt(ctx, req)
		if err != nil {
			t.Fatalf("Decrypt old ciphertext failed: %v", err)
		}

		expected := "Hello, Integration Test!"
		if string(resp.Plaintext) != expected {
			t.Errorf("Expected plaintext '%s', got '%s'", expected, string(resp.Plaintext))
		}
	})

	t.Run("EncryptWithNewVersion", func(t *testing.T) {
		plaintext := []byte("Encrypted with v2")
		req := &kmspb.EncryptRequest{
			Name:      "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			Plaintext: plaintext,
		}

		resp, err := client.Encrypt(ctx, req)
		if err != nil {
			t.Fatalf("Encrypt with v2 failed: %v", err)
		}

		decryptReq := &kmspb.DecryptRequest{
			Name:       "projects/test-project/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			Ciphertext: resp.Ciphertext,
		}

		decryptResp, err := client.Decrypt(ctx, decryptReq)
		if err != nil {
			t.Fatalf("Decrypt v2 ciphertext failed: %v", err)
		}

		if string(decryptResp.Plaintext) != string(plaintext) {
			t.Errorf("Expected plaintext '%s', got '%s'", string(plaintext), string(decryptResp.Plaintext))
		}
	})
}

func TestIntegration_MultipleKeyRings(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		req := &kmspb.CreateKeyRingRequest{
			Parent:    "projects/test-project/locations/global",
			KeyRingId: "keyring-" + string(rune('0'+i)),
		}

		_, err := client.CreateKeyRing(ctx, req)
		if err != nil {
			t.Fatalf("CreateKeyRing %d failed: %v", i, err)
		}
	}

	listReq := &kmspb.ListKeyRingsRequest{
		Parent: "projects/test-project/locations/global",
	}

	resp, err := client.ListKeyRings(ctx, listReq)
	if err != nil {
		t.Fatalf("ListKeyRings failed: %v", err)
	}

	if len(resp.KeyRings) != 3 {
		t.Errorf("Expected 3 keyrings, got %d", len(resp.KeyRings))
	}
}
