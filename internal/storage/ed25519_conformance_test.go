package storage

import (
	"crypto/ed25519"
	"errors"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// TestAsymmetricSign_Ed25519 covers the storage contract for EC_SIGN_ED25519:
// raw data is signed (pure EdDSA); digests and missing data are rejected as
// invalid arguments.
func TestAsymmetricSign_Ed25519(t *testing.T) {
	s := NewStorage()
	versionName := createConformanceKey(t, s, "ed25519-key",
		kmspb.CryptoKey_ASYMMETRIC_SIGN,
		kmspb.CryptoKeyVersion_EC_SIGN_ED25519)

	pemStr, alg, err := s.GetPublicKey(versionName)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(alg) != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		t.Fatalf("algorithm = %v, want EC_SIGN_ED25519", alg)
	}
	pub, ok := decodePublicKey(t, pemStr).(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key is not ed25519.PublicKey")
	}

	data := []byte("storage-level ed25519 data")
	sig, err := s.AsymmetricSign(versionName, nil, "", data)
	if err != nil {
		t.Fatalf("AsymmetricSign(data): %v", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("signature does not verify over raw data")
	}

	var invalid *ErrInvalidArgument
	if _, err := s.AsymmetricSign(versionName, make([]byte, 32), "SHA256", nil); !errors.As(err, &invalid) {
		t.Fatalf("digest: err = %v, want ErrInvalidArgument", err)
	}
	if _, err := s.AsymmetricSign(versionName, nil, "", nil); !errors.As(err, &invalid) {
		t.Fatalf("no data: err = %v, want ErrInvalidArgument", err)
	}
}
