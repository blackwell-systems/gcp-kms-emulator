package gcp_kms_emulator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"hash/crc32"
	"strings"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// crc32cForTest computes a CRC32C checksum for test inputs.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32cChecksum(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}

// conformanceSetup creates a server, client, and a keyring with the given ID.
// Returns the client, the keyring name, and a cleanup function.
func conformanceSetup(t *testing.T, keyringID string) (kmspb.KeyManagementServiceClient, string, func()) {
	t.Helper()
	_, lis, cleanupServer := setupTestServer(t)
	conn, cleanupClient := setupTestClient(t, lis)

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/conformance/locations/global",
		KeyRingId: keyringID,
	})
	if err != nil {
		cleanupClient()
		cleanupServer()
		t.Fatalf("CreateKeyRing(%q): %v", keyringID, err)
	}

	cleanup := func() {
		cleanupClient()
		cleanupServer()
	}
	return client, kr.Name, cleanup
}

// TestConformance_Encrypt_AAD verifies that AAD is correctly threaded through
// Encrypt/Decrypt — same AAD succeeds, different AAD fails.
func TestConformance_Encrypt_AAD(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "enc-aad-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "enc-aad-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	plaintext := []byte("hello AAD test")
	aad := []byte("my-authenticated-data")

	encResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        key.Name,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		t.Fatalf("Encrypt with AAD: %v", err)
	}

	// Decrypt with same AAD — should succeed
	decResp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        key.Name,
		Ciphertext:                  encResp.Ciphertext,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		t.Fatalf("Decrypt with correct AAD: %v", err)
	}
	if string(decResp.Plaintext) != string(plaintext) {
		t.Errorf("Plaintext mismatch: got %q, want %q", decResp.Plaintext, plaintext)
	}

	// Decrypt with different AAD — should fail
	_, err = client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        key.Name,
		Ciphertext:                  encResp.Ciphertext,
		AdditionalAuthenticatedData: []byte("wrong-aad"),
	})
	if err == nil {
		t.Fatal("Decrypt with wrong AAD should fail")
	}
}

// TestConformance_Encrypt_CRC32C_Mismatch verifies that a wrong PlaintextCrc32C
// returns codes.InvalidArgument.
func TestConformance_Encrypt_CRC32C_Mismatch(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "enc-crc-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "enc-crc-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	plaintext := []byte("crc mismatch test")
	wrongCRC := wrapperspb.Int64(12345) // intentionally wrong

	_, err = client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:            key.Name,
		Plaintext:       plaintext,
		PlaintextCrc32C: wrongCRC,
	})
	if err == nil {
		t.Fatal("Encrypt with wrong CRC32C should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// TestConformance_Encrypt_ResponseName_IsVersion verifies that EncryptResponse.Name
// is a version name (contains "cryptoKeyVersions/").
func TestConformance_Encrypt_ResponseName_IsVersion(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "enc-name-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "enc-name-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	encResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      key.Name,
		Plaintext: []byte("version name test"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !strings.Contains(encResp.Name, "cryptoKeyVersions/") {
		t.Errorf("EncryptResponse.Name %q should contain 'cryptoKeyVersions/'", encResp.Name)
	}
}

// TestConformance_Encrypt_WrongPurpose verifies that calling Encrypt on a MAC key
// returns codes.FailedPrecondition.
func TestConformance_Encrypt_WrongPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "enc-wp-ring")
	defer cleanup()
	ctx := context.Background()

	macKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "mac-key-for-enc",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey(MAC): %v", err)
	}

	_, err = client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      macKey.Name,
		Plaintext: []byte("should fail"),
	})
	if err == nil {
		t.Fatal("Encrypt on MAC key should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// TestConformance_Decrypt_WrongPurpose verifies that calling Decrypt on an
// ASYMMETRIC_SIGN key returns codes.FailedPrecondition.
func TestConformance_Decrypt_WrongPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "dec-wp-ring")
	defer cleanup()
	ctx := context.Background()

	signKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "sign-key-for-dec",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey(ASYMMETRIC_SIGN): %v", err)
	}

	_, err = client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       signKey.Name,
		Ciphertext: []byte("fake ciphertext"),
	})
	if err == nil {
		t.Fatal("Decrypt on ASYMMETRIC_SIGN key should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// TestConformance_Decrypt_UsedPrimary verifies that UsedPrimary=true when
// decrypting ciphertext encrypted with the current primary version.
func TestConformance_Decrypt_UsedPrimary(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "dec-primary-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "dec-primary-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	encResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      key.Name,
		Plaintext: []byte("used primary test"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decResp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       key.Name,
		Ciphertext: encResp.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !decResp.UsedPrimary {
		t.Error("Expected UsedPrimary=true when decrypting with primary version")
	}
}

// TestConformance_CreateCryptoKey_UnspecifiedPurpose verifies that creating a key
// with UNSPECIFIED purpose returns codes.InvalidArgument.
func TestConformance_CreateCryptoKey_UnspecifiedPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "ckk-purpose-ring")
	defer cleanup()
	ctx := context.Background()

	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "unspecified-purpose-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED,
		},
	})
	if err == nil {
		t.Fatal("CreateCryptoKey with UNSPECIFIED purpose should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// TestConformance_UpdateCryptoKey_MaskRespected verifies that updating only
// "labels" leaves version_template unchanged.
func TestConformance_UpdateCryptoKey_MaskRespected(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "upd-ck-mask-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "upd-mask-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	updatedKey, err := client.UpdateCryptoKey(ctx, &kmspb.UpdateCryptoKeyRequest{
		CryptoKey: &kmspb.CryptoKey{
			Name:   key.Name,
			Labels: map[string]string{"env": "test"},
			// Intentionally omit VersionTemplate to verify it doesn't get zeroed
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	})
	if err != nil {
		t.Fatalf("UpdateCryptoKey: %v", err)
	}

	if updatedKey.Labels["env"] != "test" {
		t.Errorf("Expected label env=test, got %v", updatedKey.Labels)
	}
	// VersionTemplate should be unchanged (SOFTWARE protection level)
	if updatedKey.VersionTemplate != nil &&
		updatedKey.VersionTemplate.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		t.Errorf("VersionTemplate.ProtectionLevel changed unexpectedly: %v",
			updatedKey.VersionTemplate.ProtectionLevel)
	}
}

// TestConformance_UpdateCryptoKeyVersion_InvalidTransition verifies that setting
// state=DESTROY_SCHEDULED via UpdateCryptoKeyVersion returns an error.
func TestConformance_UpdateCryptoKeyVersion_InvalidTransition(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "upd-ckv-trans-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "upd-trans-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	versionName := key.Primary.Name

	_, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Name:  versionName,
			State: kmspb.CryptoKeyVersion_DESTROY_SCHEDULED,
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	if err == nil {
		t.Fatal("UpdateCryptoKeyVersion to DESTROY_SCHEDULED should fail")
	}
	// Should be FailedPrecondition (invalid state transition)
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition && st.Code() != codes.InvalidArgument {
		t.Errorf("Expected FailedPrecondition or InvalidArgument, got %v", st.Code())
	}
}

// TestConformance_DestroyCryptoKeyVersion_Idempotent verifies that destroying a
// version twice does not error on the second call.
func TestConformance_DestroyCryptoKeyVersion_Idempotent(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "destroy-idem-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "destroy-idem-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	versionName := key.Primary.Name

	// First destroy
	_, err = client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("First DestroyCryptoKeyVersion: %v", err)
	}

	// Second destroy — should succeed (idempotent)
	_, err = client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("Second DestroyCryptoKeyVersion should be idempotent, got: %v", err)
	}
}

// TestConformance_DestroyCryptoKeyVersion_DestroyTime verifies that the response
// has a non-nil DestroyTime after scheduling destruction.
func TestConformance_DestroyCryptoKeyVersion_DestroyTime(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "destroy-time-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "destroy-time-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	resp, err := client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: key.Primary.Name,
	})
	if err != nil {
		t.Fatalf("DestroyCryptoKeyVersion: %v", err)
	}

	if resp.DestroyTime == nil {
		t.Error("Expected non-nil DestroyTime in DestroyCryptoKeyVersion response")
	}
	if resp.State != kmspb.CryptoKeyVersion_DESTROY_SCHEDULED {
		t.Errorf("Expected state DESTROY_SCHEDULED, got %v", resp.State)
	}
}

// TestConformance_MacSign_WrongPurpose verifies that calling MacSign on an
// ENCRYPT_DECRYPT key returns codes.FailedPrecondition.
func TestConformance_MacSign_WrongPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "mac-wp-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "enc-key-for-mac",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	_, err = client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: key.Primary.Name,
		Data: []byte("should fail"),
	})
	if err == nil {
		t.Fatal("MacSign on ENCRYPT_DECRYPT key should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// TestConformance_MacSign_CRC32C_Mismatch verifies that calling MacSign with a
// wrong DataCrc32C returns codes.InvalidArgument.
func TestConformance_MacSign_CRC32C_Mismatch(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "mac-crc-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "mac-crc-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	data := []byte("mac crc test data")
	wrongCRC := wrapperspb.Int64(99999) // intentionally wrong

	_, err = client.MacSign(ctx, &kmspb.MacSignRequest{
		Name:       key.Primary.Name,
		Data:       data,
		DataCrc32C: wrongCRC,
	})
	if err == nil {
		t.Fatal("MacSign with wrong CRC32C should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// TestConformance_RawEncrypt_WrongPurpose verifies that calling RawEncrypt on an
// ENCRYPT_DECRYPT key (not RAW_ENCRYPT_DECRYPT) returns codes.FailedPrecondition.
func TestConformance_RawEncrypt_WrongPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "raw-wp-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "enc-key-for-raw",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	_, err = client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:      key.Primary.Name,
		Plaintext: []byte("should fail"),
	})
	if err == nil {
		t.Fatal("RawEncrypt on ENCRYPT_DECRYPT key should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// TestConformance_ImportCryptoKeyVersion_UnspecifiedAlgorithm verifies that calling
// ImportCryptoKeyVersion with UNSPECIFIED algorithm returns codes.InvalidArgument.
func TestConformance_ImportCryptoKeyVersion_UnspecifiedAlgorithm(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "import-alg-ring")
	defer cleanup()
	ctx := context.Background()

	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "import-alg-key",
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	cryptoKeyName := krName + "/cryptoKeys/import-alg-key"

	importJobResp, err := client.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
		Parent:      krName,
		ImportJobId: "ij-alg-test",
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_3072_SHA1_AES_256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
	})
	if err != nil {
		t.Fatalf("CreateImportJob: %v", err)
	}

	_, err = client.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     cryptoKeyName,
		Algorithm:  kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED,
		ImportJob:  importJobResp.Name,
		WrappedKey: []byte("fake-wrapped-key"),
	})
	if err == nil {
		t.Fatal("ImportCryptoKeyVersion with UNSPECIFIED algorithm should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// TestConformance_AsymmetricSign_DataField verifies that AsymmetricSign can be
// called with the Data field (raw data) and produces a valid signature.
func TestConformance_AsymmetricSign_DataField(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "asym-data-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "ec-sign-data-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	versionName := key.Primary.Name
	data := []byte("raw data to sign via Data field")

	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: versionName,
		Data: data,
	})
	if err != nil {
		t.Fatalf("AsymmetricSign with Data field: %v", err)
	}
	if len(signResp.Signature) == 0 {
		t.Fatal("Expected non-empty signature")
	}

	// Signature is non-empty; verify with public key
	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}
	rawPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	// Storage hashes internally for rawData with P256 SHA256; verify the hash ourselves
	ecPubKey, ok2 := rawPubKey.(*ecdsa.PublicKey)
	if !ok2 {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", rawPubKey)
	}
	hashBytes := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(ecPubKey, hashBytes[:], signResp.Signature) {
		t.Error("ECDSA signature verification failed for Data field signing")
	}
}

// TestConformance_AsymmetricSign_WrongPurpose verifies that calling AsymmetricSign
// on an ASYMMETRIC_DECRYPT key returns codes.FailedPrecondition.
func TestConformance_AsymmetricSign_WrongPurpose(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "asym-sign-wp-ring")
	defer cleanup()
	ctx := context.Background()

	// Create an ASYMMETRIC_DECRYPT key — cannot be used for signing
	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "rsa-decrypt-for-sign",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey(ASYMMETRIC_DECRYPT): %v", err)
	}

	data := []byte("should fail")
	hash := sha256.Sum256(data)

	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: key.Primary.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: hash[:]},
		},
	})
	if err == nil {
		t.Fatal("AsymmetricSign on ASYMMETRIC_DECRYPT key should fail")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// TestConformance_AsymmetricDecrypt_SHA1OAEP verifies that an RSA_DECRYPT_OAEP_2048_SHA1
// key can decrypt ciphertext encrypted with SHA-1 OAEP.
func TestConformance_AsymmetricDecrypt_SHA1OAEP(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "asym-dec-sha1-ring")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "rsa-oaep-sha1-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey(RSA_DECRYPT_OAEP_2048_SHA1): %v", err)
	}

	versionName := key.Primary.Name

	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected RSA public key, got %T", pubKey)
	}

	plaintext := []byte("sha1 oaep test plaintext")
	// Encrypt locally with SHA-1 OAEP
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP(SHA1): %v", err)
	}

	decResp, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       versionName,
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("AsymmetricDecrypt with SHA1 OAEP ciphertext: %v", err)
	}

	if string(decResp.Plaintext) != string(plaintext) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decResp.Plaintext, plaintext)
	}
}
