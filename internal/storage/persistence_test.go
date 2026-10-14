package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const persistenceTestKeyRing = "projects/test/locations/global/keyRings/persisted"

func newPersistentStorage(t *testing.T, dataDir string) *Storage {
	t.Helper()

	s := NewStorage()
	if err := s.EnablePersistence(dataDir); err != nil {
		t.Fatalf("EnablePersistence failed: %v", err)
	}
	return s
}

func mustCreateKey(t *testing.T, s *Storage, keyID string, purpose kmspb.CryptoKey_CryptoKeyPurpose, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) string {
	t.Helper()

	key, err := s.CreateCryptoKey(persistenceTestKeyRing, keyID, purpose, &kmspb.CryptoKeyVersionTemplate{Algorithm: algorithm}, nil)
	if err != nil {
		t.Fatalf("CreateCryptoKey(%s) failed: %v", keyID, err)
	}
	return key.Name
}

func rsaPublicKeyFromPEM(t *testing.T, publicKeyPEM string) *rsa.PublicKey {
	t.Helper()

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected an RSA public key, got %T", parsed)
	}
	return publicKey
}

func TestPersistence_KeyMaterialSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	original := newPersistentStorage(t, dataDir)

	if _, err := original.CreateKeyRing(persistenceTestKeyRing); err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}
	symmetricKey := mustCreateKey(t, original, "symmetric", kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION)
	decryptKey := mustCreateKey(t, original, "rsa-decrypt", kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256)
	signKey := mustCreateKey(t, original, "ec-sign", kmspb.CryptoKey_ASYMMETRIC_SIGN, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
	macKey := mustCreateKey(t, original, "hmac", kmspb.CryptoKey_MAC, kmspb.CryptoKeyVersion_HMAC_SHA256)

	plaintext := []byte("sealed before the restart")

	symmetricCiphertext, _, err := original.Encrypt(symmetricKey, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decryptVersion := decryptKey + "/cryptoKeyVersions/1"
	decryptPublicKeyPEM, _, err := original.GetPublicKey(decryptVersion)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	asymmetricCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKeyFromPEM(t, decryptPublicKeyPEM), plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP failed: %v", err)
	}

	signPublicKeyPEM, _, err := original.GetPublicKey(signKey + "/cryptoKeyVersions/1")
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	macVersion := macKey + "/cryptoKeyVersions/1"
	originalMAC, err := original.MacSign(macVersion, plaintext)
	if err != nil {
		t.Fatalf("MacSign failed: %v", err)
	}

	restored := newPersistentStorage(t, dataDir)

	t.Run("symmetric ciphertext still decrypts", func(t *testing.T) {
		decrypted, _, err := restored.Decrypt(symmetricKey, symmetricCiphertext, nil)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("asymmetric ciphertext still decrypts", func(t *testing.T) {
		decrypted, err := restored.AsymmetricDecrypt(decryptVersion, asymmetricCiphertext)
		if err != nil {
			t.Fatalf("AsymmetricDecrypt failed: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("expected %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("public keys are unchanged", func(t *testing.T) {
		for version, want := range map[string]string{
			decryptVersion:                   decryptPublicKeyPEM,
			signKey + "/cryptoKeyVersions/1": signPublicKeyPEM,
		} {
			got, _, err := restored.GetPublicKey(version)
			if err != nil {
				t.Fatalf("GetPublicKey(%s) failed: %v", version, err)
			}
			if got != want {
				t.Errorf("public key of %s changed across restart", version)
			}
		}
	})

	t.Run("MAC key is unchanged", func(t *testing.T) {
		restoredMAC, err := restored.MacSign(macVersion, plaintext)
		if err != nil {
			t.Fatalf("MacSign failed: %v", err)
		}
		if !bytes.Equal(restoredMAC, originalMAC) {
			t.Error("MAC changed across restart")
		}
	})
}

func TestPersistence_MetadataSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	original := newPersistentStorage(t, dataDir)

	if _, err := original.CreateKeyRing(persistenceTestKeyRing); err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}
	keyName := mustCreateKey(t, original, "rotated", kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION)

	if _, err := original.CreateCryptoKeyVersion(keyName, nil); err != nil {
		t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
	}
	if _, err := original.CreateCryptoKeyVersion(keyName, nil); err != nil {
		t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
	}
	if _, err := original.UpdateCryptoKeyPrimaryVersion(keyName, keyName+"/cryptoKeyVersions/2"); err != nil {
		t.Fatalf("UpdateCryptoKeyPrimaryVersion failed: %v", err)
	}
	if _, err := original.UpdateCryptoKeyVersion(keyName+"/cryptoKeyVersions/1", kmspb.CryptoKeyVersion_DISABLED, nil); err != nil {
		t.Fatalf("UpdateCryptoKeyVersion failed: %v", err)
	}
	if _, err := original.DestroyCryptoKeyVersion(keyName + "/cryptoKeyVersions/3"); err != nil {
		t.Fatalf("DestroyCryptoKeyVersion failed: %v", err)
	}
	if _, err := original.UpdateCryptoKey(keyName, &kmspb.CryptoKey{
		Labels:                   map[string]string{"env": "dev"},
		RotationSchedule:         &kmspb.CryptoKey_RotationPeriod{RotationPeriod: durationpb.New(90 * 24 * time.Hour)},
		DestroyScheduledDuration: durationpb.New(24 * time.Hour),
	}, &fieldmaskpb.FieldMask{Paths: []string{"labels", "rotation_period", "destroy_scheduled_duration"}}); err != nil {
		t.Fatalf("UpdateCryptoKey failed: %v", err)
	}

	restored := newPersistentStorage(t, dataDir)

	t.Run("snapshot round-trips unchanged", func(t *testing.T) {
		before, err := encodeSnapshot(original.keyrings)
		if err != nil {
			t.Fatalf("encodeSnapshot(original) failed: %v", err)
		}
		after, err := encodeSnapshot(restored.keyrings)
		if err != nil {
			t.Fatalf("encodeSnapshot(restored) failed: %v", err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("restored state differs from the original\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("crypto key metadata", func(t *testing.T) {
		key, err := restored.GetCryptoKey(keyName)
		if err != nil {
			t.Fatalf("GetCryptoKey failed: %v", err)
		}
		if key.Primary.Name != keyName+"/cryptoKeyVersions/2" {
			t.Errorf("expected primary version 2, got %s", key.Primary.Name)
		}
		if key.Labels["env"] != "dev" {
			t.Errorf("expected label env=dev, got %v", key.Labels)
		}
		if key.GetRotationPeriod().AsDuration() != 90*24*time.Hour {
			t.Errorf("expected 90 day rotation period, got %v", key.GetRotationPeriod())
		}
		if key.DestroyScheduledDuration.AsDuration() != 24*time.Hour {
			t.Errorf("expected 24h destroy scheduled duration, got %v", key.DestroyScheduledDuration)
		}
		if key.VersionTemplate.GetAlgorithm() != kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
			t.Errorf("expected version template algorithm to survive, got %v", key.VersionTemplate)
		}
	})

	t.Run("version states", func(t *testing.T) {
		for version, want := range map[string]kmspb.CryptoKeyVersion_CryptoKeyVersionState{
			keyName + "/cryptoKeyVersions/1": kmspb.CryptoKeyVersion_DISABLED,
			keyName + "/cryptoKeyVersions/2": kmspb.CryptoKeyVersion_ENABLED,
			keyName + "/cryptoKeyVersions/3": kmspb.CryptoKeyVersion_DESTROY_SCHEDULED,
		} {
			got, err := restored.GetCryptoKeyVersion(version)
			if err != nil {
				t.Fatalf("GetCryptoKeyVersion(%s) failed: %v", version, err)
			}
			if got.State != want {
				t.Errorf("expected %s to be %v, got %v", version, want, got.State)
			}
		}
	})

	t.Run("version numbering continues", func(t *testing.T) {
		version, err := restored.CreateCryptoKeyVersion(keyName, nil)
		if err != nil {
			t.Fatalf("CreateCryptoKeyVersion failed: %v", err)
		}
		if !strings.HasSuffix(version.Name, "/cryptoKeyVersions/4") {
			t.Errorf("expected version 4, got %s", version.Name)
		}
	})
}

func TestPersistence_ImportJobSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	original := newPersistentStorage(t, dataDir)

	if _, err := original.CreateKeyRing(persistenceTestKeyRing); err != nil {
		t.Fatalf("CreateKeyRing failed: %v", err)
	}
	keyName := mustCreateKey(t, original, "imported", kmspb.CryptoKey_ENCRYPT_DECRYPT, kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION)
	importJob, err := original.CreateImportJob(persistenceTestKeyRing, "job", int32(kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256), int32(kmspb.ProtectionLevel_SOFTWARE))
	if err != nil {
		t.Fatalf("CreateImportJob failed: %v", err)
	}

	restored := newPersistentStorage(t, dataDir)

	restoredJob, err := restored.GetImportJob(importJob.Name)
	if err != nil {
		t.Fatalf("GetImportJob failed: %v", err)
	}
	if restoredJob.PublicKeyPEM != importJob.PublicKeyPEM {
		t.Error("import job wrapping key changed across restart")
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKeyFromPEM(t, importJob.PublicKeyPEM), aesKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP failed: %v", err)
	}
	if _, err := restored.ImportCryptoKeyVersion(keyName, int32(kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION), importJob.Name, wrappedKey); err != nil {
		t.Errorf("ImportCryptoKeyVersion with the restored job failed: %v", err)
	}
}

func TestPersistence_StartsEmptyAndWritesStateFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "not", "created", "yet")
	s := newPersistentStorage(t, dataDir)

	keyRings, _, err := s.ListKeyRings("projects/test/locations/global", 0, "")
	if err != nil {
		t.Fatalf("ListKeyRings failed: %v", err)
	}
	if len(keyRings) != 0 {
		t.Errorf("expected no key rings, got %d", len(keyRings))
	}

	info, err := os.Stat(filepath.Join(dataDir, StateFileName))
	if err != nil {
		t.Fatalf("expected a state file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("expected state file mode 0600, got %o", mode)
	}
}

func TestPersistence_RejectsUnreadableStateFile(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt JSON":           "{not json",
		"unknown format version": `{"formatVersion": 99, "keyRings": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			statePath := filepath.Join(dataDir, StateFileName)
			if err := os.WriteFile(statePath, []byte(content), 0o600); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}

			if err := NewStorage().EnablePersistence(dataDir); err == nil {
				t.Fatal("expected EnablePersistence to fail")
			}

			kept, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}
			if string(kept) != content {
				t.Error("an unreadable state file must be left untouched")
			}
		})
	}
}
