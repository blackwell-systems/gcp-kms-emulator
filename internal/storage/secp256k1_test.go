package storage

import (
	"crypto/sha256"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

func TestAsymmetricSign_Secp256k1(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "secp256k1-sign-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256)

	data := []byte("ethereum-style payload")
	digest := sha256.Sum256(data)

	sig, err := s.AsymmetricSign(versionName, digest[:], "SHA256", nil)
	if err != nil {
		t.Fatalf("AsymmetricSign(digest): %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	pemStr, alg, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if alg != int32(kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256) {
		t.Fatalf("unexpected algorithm: got %v, want EC_SIGN_SECP256K1_SHA256", alg)
	}

	if err := VerifySecp256k1ASN1(pemStr, digest[:], sig); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func TestAsymmetricSign_Secp256k1_DataField(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "secp256k1-raw-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256)

	rawData := []byte("raw payload hashed internally")
	sig, err := s.AsymmetricSign(versionName, nil, "", rawData)
	if err != nil {
		t.Fatalf("AsymmetricSign(rawData): %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	pemStr, _, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	digest := sha256.Sum256(rawData)
	if err := VerifySecp256k1ASN1(pemStr, digest[:], sig); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func TestGenerateSecp256k1KeyMaterial(t *testing.T) {
	material, err := generateSecp256k1KeyMaterial()
	if err != nil {
		t.Fatalf("generateSecp256k1KeyMaterial: %v", err)
	}
	if len(material.PrivateKeyDER) == 0 {
		t.Fatal("expected non-empty private key DER")
	}
	if material.PublicKeyPEM == "" {
		t.Fatal("expected non-empty public key PEM")
	}

	privKey, err := parseSecp256k1PrivateKeyPKCS8(material.PrivateKeyDER)
	if err != nil {
		t.Fatalf("parseSecp256k1PrivateKeyPKCS8: %v", err)
	}
	pubKey, err := parseSecp256k1PublicKeyPEM(material.PublicKeyPEM)
	if err != nil {
		t.Fatalf("parseSecp256k1PublicKeyPEM: %v", err)
	}
	if !privKey.PubKey().IsEqual(pubKey) {
		t.Fatal("parsed public key does not match private key")
	}
}

func TestGetPublicKey_Secp256k1_NonExistentKey(t *testing.T) {
	s := NewStorage()

	_, _, err := s.GetPublicKey("projects/test/locations/us/keyRings/ring/cryptoKeys/nonexistent/cryptoKeyVersions/1")
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}

	if _, ok := err.(*ErrNotFound); !ok {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestGetPublicKey_Secp256k1_DisabledKey(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "secp256k1-disabled-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256)

	// Disable the key version
	_, err := s.UpdateCryptoKeyVersion(versionName, kmspb.CryptoKeyVersion_DISABLED, nil)
	if err != nil {
		t.Fatalf("UpdateCryptoKeyVersion: %v", err)
	}

	// GetPublicKey should still work on disabled keys (matches GCP behavior)
	_, _, err = s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey on disabled key: %v (should succeed)", err)
	}
}

func TestVerifySecp256k1ASN1_InvalidSignature(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "secp256k1-verify-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256)

	pemStr, _, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	invalidSig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01} // Malformed DER

	err = VerifySecp256k1ASN1(pemStr, digest[:], invalidSig)
	if err == nil {
		t.Fatal("expected verification error for invalid signature, got nil")
	}
}

func TestParseSecp256k1PublicKeyPEM_TrailingData(t *testing.T) {
	material, err := generateSecp256k1KeyMaterial()
	if err != nil {
		t.Fatalf("generateSecp256k1KeyMaterial: %v", err)
	}

	// Append garbage to the PEM
	pemWithTrailing := material.PublicKeyPEM + "TRAILING_GARBAGE"

	_, err = parseSecp256k1PublicKeyPEM(pemWithTrailing)
	if err == nil {
		t.Fatal("expected error for PEM with trailing data, got nil")
	}
	if err.Error() != "PEM contains unexpected trailing data (16 bytes)" {
		t.Fatalf("unexpected error message: %v", err)
	}
}
