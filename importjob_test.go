package gcp_kms_emulator_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

func TestIntegration_ImportJobLifecycle(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create a keyring first
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "import-test-keyring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	keyringName := "projects/test-project/locations/global/keyRings/import-test-keyring"

	t.Run("CreateImportJob", func(t *testing.T) {
		resp, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
			Parent:      keyringName,
			ImportJobId: "import-job-1",
			ImportJob: &kmspb.ImportJob{
				ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256,
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		})
		if err != nil {
			t.Fatalf("CreateImportJob failed: %v", err)
		}

		expectedName := keyringName + "/importJobs/import-job-1"
		if resp.Name != expectedName {
			t.Errorf("Expected name %q, got %q", expectedName, resp.Name)
		}
		if resp.State != kmspb.ImportJob_ACTIVE {
			t.Errorf("Expected state ACTIVE, got %v", resp.State)
		}
		if resp.PublicKey == nil || resp.PublicKey.Pem == "" {
			t.Error("Expected non-empty public key PEM")
		}
		if resp.CreateTime == nil {
			t.Error("Expected non-nil CreateTime")
		}
		if resp.ExpireTime == nil {
			t.Error("Expected non-nil ExpireTime")
		}
	})

	t.Run("CreateImportJob_Duplicate", func(t *testing.T) {
		_, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
			Parent:      keyringName,
			ImportJobId: "import-job-1",
			ImportJob: &kmspb.ImportJob{
				ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256,
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		})
		if err == nil {
			t.Fatal("Expected error for duplicate import job, got nil")
		}
	})

	t.Run("GetImportJob", func(t *testing.T) {
		importJobName := keyringName + "/importJobs/import-job-1"
		resp, err := client.GetImportJob(ctx, &kmspb.GetImportJobRequest{
			Name: importJobName,
		})
		if err != nil {
			t.Fatalf("GetImportJob failed: %v", err)
		}

		if resp.Name != importJobName {
			t.Errorf("Expected name %q, got %q", importJobName, resp.Name)
		}
		if resp.State != kmspb.ImportJob_ACTIVE {
			t.Errorf("Expected state ACTIVE, got %v", resp.State)
		}
	})

	t.Run("GetImportJob_NotFound", func(t *testing.T) {
		_, err := client.GetImportJob(ctx, &kmspb.GetImportJobRequest{
			Name: keyringName + "/importJobs/nonexistent",
		})
		if err == nil {
			t.Fatal("Expected error for nonexistent import job, got nil")
		}
	})

	t.Run("ListImportJobs", func(t *testing.T) {
		// Create a second import job
		_, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
			Parent:      keyringName,
			ImportJobId: "import-job-2",
			ImportJob: &kmspb.ImportJob{
				ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256,
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		})
		if err != nil {
			t.Fatalf("CreateImportJob (second) failed: %v", err)
		}

		resp, err := client.ListImportJobs(ctx, &kmspb.ListImportJobsRequest{
			Parent: keyringName,
		})
		if err != nil {
			t.Fatalf("ListImportJobs failed: %v", err)
		}

		if len(resp.ImportJobs) != 2 {
			t.Errorf("Expected 2 import jobs, got %d", len(resp.ImportJobs))
		}
		if resp.TotalSize != 2 {
			t.Errorf("Expected TotalSize 2, got %d", resp.TotalSize)
		}
	})
}

func TestIntegration_ImportCryptoKeyVersion(t *testing.T) {
	_, lis, cleanupServer := setupTestServer(t)
	defer cleanupServer()

	conn, cleanupClient := setupTestClient(t, lis)
	defer cleanupClient()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Setup: create keyring, crypto key, and import job
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test-project/locations/global",
		KeyRingId: "import-version-keyring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}

	keyringName := "projects/test-project/locations/global/keyRings/import-version-keyring"

	_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyringName,
		CryptoKeyId: "import-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey failed: %v", err)
	}

	cryptoKeyName := keyringName + "/cryptoKeys/import-key"

	importJobResp, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
		Parent:      keyringName,
		ImportJobId: "ij-for-import",
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
	})
	if err != nil {
		t.Fatalf("CreateImportJob failed: %v", err)
	}

	importJobName := importJobResp.Name

	// Parse the import job's public key
	pubPEM := importJobResp.PublicKey.Pem
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("Failed to decode import job public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Public key is not RSA")
	}

	// Generate a 32-byte AES key and wrap it with the import job's public key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, aesKey, nil)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	t.Run("ImportCryptoKeyVersion", func(t *testing.T) {
		resp, err := client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
			Parent:     cryptoKeyName,
			Algorithm:  kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ImportJob:  importJobName,
			WrappedKey: wrappedKey,
		})
		if err != nil {
			t.Fatalf("ImportCryptoKeyVersion failed: %v", err)
		}

		if resp.State != kmspb.CryptoKeyVersion_ENABLED {
			t.Errorf("Expected state ENABLED, got %v", resp.State)
		}
		if resp.Algorithm != kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
			t.Errorf("Expected algorithm GOOGLE_SYMMETRIC_ENCRYPTION, got %v", resp.Algorithm)
		}
		if resp.Name == "" {
			t.Error("Expected non-empty version name")
		}
	})

	t.Run("ImportCryptoKeyVersion_MissingFields", func(t *testing.T) {
		_, err := client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
			Parent: "",
		})
		if err == nil {
			t.Fatal("Expected error for missing parent")
		}

		_, err = client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
			Parent:    cryptoKeyName,
			ImportJob: "",
		})
		if err == nil {
			t.Fatal("Expected error for missing import_job")
		}
	})
}
