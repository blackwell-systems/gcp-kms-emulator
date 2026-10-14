package gcp_kms_emulator_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/storage"
)

func TestIntegration_PersistenceAcrossRestart(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(server.DataDirEnv, dataDir)

	ctx := context.Background()
	keyRingName := "projects/test/locations/global/keyRings/persisted"
	versionName := keyRingName + "/cryptoKeys/sealing/cryptoKeyVersions/1"
	plaintext := []byte("content encryption key")

	var publicKeyPEM string
	var ciphertext []byte

	firstRunPassed := t.Run("first run seals to a fresh key", func(t *testing.T) {
		_, lis, cleanup := setupTestServer(t)
		defer cleanup()
		conn, connCleanup := setupTestClient(t, lis)
		defer connCleanup()
		client := kmspb.NewKeyManagementServiceClient(conn)

		if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
			Parent:    "projects/test/locations/global",
			KeyRingId: "persisted",
		}); err != nil {
			t.Fatalf("CreateKeyRing failed: %v", err)
		}
		if _, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
			Parent:      keyRingName,
			CryptoKeyId: "sealing",
			CryptoKey: &kmspb.CryptoKey{
				Purpose:         kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256},
			},
		}); err != nil {
			t.Fatalf("CreateCryptoKey failed: %v", err)
		}

		publicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err != nil {
			t.Fatalf("GetPublicKey failed: %v", err)
		}
		publicKeyPEM = publicKey.Pem

		block, _ := pem.Decode([]byte(publicKeyPEM))
		if block == nil {
			t.Fatal("failed to decode public key PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse public key: %v", err)
		}
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed.(*rsa.PublicKey), plaintext, nil)
		if err != nil {
			t.Fatalf("EncryptOAEP failed: %v", err)
		}
	})
	if !firstRunPassed {
		t.FailNow()
	}

	if _, err := os.Stat(filepath.Join(dataDir, storage.StateFileName)); err != nil {
		t.Fatalf("expected a state file after the first run: %v", err)
	}

	t.Run("second run opens what the first sealed", func(t *testing.T) {
		_, lis, cleanup := setupTestServer(t)
		defer cleanup()
		conn, connCleanup := setupTestClient(t, lis)
		defer connCleanup()
		client := kmspb.NewKeyManagementServiceClient(conn)

		if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
			Parent:    "projects/test/locations/global",
			KeyRingId: "persisted",
		}); err == nil {
			t.Error("expected the key ring to already exist after a restart")
		}

		publicKey, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err != nil {
			t.Fatalf("GetPublicKey failed: %v", err)
		}
		if publicKey.Pem != publicKeyPEM {
			t.Error("public key changed across restart")
		}

		decrypted, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{Name: versionName, Ciphertext: ciphertext})
		if err != nil {
			t.Fatalf("AsymmetricDecrypt failed: %v", err)
		}
		if !bytes.Equal(decrypted.Plaintext, plaintext) {
			t.Errorf("expected %q, got %q", plaintext, decrypted.Plaintext)
		}
	})
}
