package gcp_kms_emulator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/storage"
)

func TestIntegration_AsymmetricSignVerify(t *testing.T) {
	_, lis, cleanup := setupTestServer(t)
	defer cleanup()

	conn, connCleanup := setupTestClient(t, lis)
	defer connCleanup()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring
	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/us-central1",
		KeyRingId: "asymmetric-sign-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}

	// Create ASYMMETRIC_SIGN key with EC_SIGN_P256_SHA256
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "ec-sign-key",
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

	versionName := cryptoKey.Primary.Name

	// Hash data with sha256
	data := []byte("test data to sign")
	hash := sha256.Sum256(data)

	// Sign
	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: versionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: hash[:]},
		},
	})
	if err != nil {
		t.Fatalf("AsymmetricSign: %v", err)
	}

	if len(signResp.Signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// GetPublicKey
	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	if pubKeyResp.Pem == "" {
		t.Fatal("expected non-empty PEM")
	}

	// Parse PEM public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", pubKey)
	}

	// Verify signature
	if !ecdsa.VerifyASN1(ecPubKey, hash[:], signResp.Signature) {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestIntegration_AsymmetricSignVerify_Secp256k1(t *testing.T) {
	_, lis, cleanup := setupTestServer(t)
	defer cleanup()

	conn, connCleanup := setupTestClient(t, lis)
	defer connCleanup()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/us-central1",
		KeyRingId: "secp256k1-sign-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}

	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "secp256k1-sign-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	versionName := cryptoKey.Primary.Name
	if cryptoKey.Primary.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("unexpected key algorithm: got %v, want EC_SIGN_SECP256K1_SHA256", cryptoKey.Primary.Algorithm)
	}

	data := []byte("evm transaction hash input")
	hash := sha256.Sum256(data)

	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: versionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: hash[:]},
		},
	})
	if err != nil {
		t.Fatalf("AsymmetricSign(digest): %v", err)
	}
	if len(signResp.Signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if pubKeyResp.Pem == "" {
		t.Fatal("expected non-empty PEM")
	}
	if pubKeyResp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("unexpected public key algorithm: got %v, want EC_SIGN_SECP256K1_SHA256", pubKeyResp.Algorithm)
	}

	if err := storage.VerifySecp256k1ASN1(pubKeyResp.Pem, hash[:], signResp.Signature); err != nil {
		t.Fatalf("verify signature: %v", err)
	}

	rawSignResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: versionName,
		Data: data,
	})
	if err != nil {
		t.Fatalf("AsymmetricSign(data): %v", err)
	}
	if len(rawSignResp.Signature) == 0 {
		t.Fatal("expected non-empty signature for raw data sign")
	}
	if err := storage.VerifySecp256k1ASN1(pubKeyResp.Pem, hash[:], rawSignResp.Signature); err != nil {
		t.Fatalf("verify raw-data signature: %v", err)
	}
}

func TestIntegration_AsymmetricDecrypt(t *testing.T) {
	_, lis, cleanup := setupTestServer(t)
	defer cleanup()

	conn, connCleanup := setupTestClient(t, lis)
	defer connCleanup()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring
	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/us-central1",
		KeyRingId: "asymmetric-decrypt-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}

	// Create ASYMMETRIC_DECRYPT key with RSA_DECRYPT_OAEP_2048_SHA256
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "rsa-decrypt-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	versionName := cryptoKey.Primary.Name

	// Get public key
	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	// Parse RSA public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", pubKey)
	}

	// Encrypt with RSA OAEP
	plaintext := []byte("hello, asymmetric decryption!")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}

	// Decrypt via emulator
	decryptResp, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       versionName,
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("AsymmetricDecrypt: %v", err)
	}

	if string(decryptResp.Plaintext) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", decryptResp.Plaintext, plaintext)
	}
}

func TestIntegration_GetPublicKey(t *testing.T) {
	_, lis, cleanup := setupTestServer(t)
	defer cleanup()

	conn, connCleanup := setupTestClient(t, lis)
	defer connCleanup()

	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// Create keyring
	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/us-central1",
		KeyRingId: "get-pubkey-ring",
	})
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}

	// Create ASYMMETRIC_SIGN key
	cryptoKey, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "ec-key-for-pubkey",
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

	versionName := cryptoKey.Primary.Name

	// Get public key
	pubKeyResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: versionName,
	})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	// Verify PEM is non-empty
	if pubKeyResp.Pem == "" {
		t.Fatal("expected non-empty PEM in GetPublicKey response")
	}

	// Verify PEM is parseable
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		t.Fatal("failed to decode PEM block from GetPublicKey response")
	}

	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}

	// Verify algorithm is set
	if pubKeyResp.Algorithm == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		t.Fatal("expected algorithm to be set in GetPublicKey response")
	}
}
