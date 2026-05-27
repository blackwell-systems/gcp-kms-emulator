// keymaterial.go provides asymmetric key material types, import job storage,
// and key generation logic shared across KMS RPC handlers (CreateCryptoKeyVersion,
// ImportCryptoKeyVersion, GetPublicKey, AsymmetricSign, AsymmetricDecrypt, MacSign,
// MacVerify, RawEncrypt, RawDecrypt).
package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// AsymmetricKeyMaterial holds DER-encoded private key and PEM-encoded public key
// for RSA and EC key versions.
type AsymmetricKeyMaterial struct {
	PrivateKeyDER []byte
	PublicKeyPEM  string
}

// StoredImportJob represents an import job persisted in the emulator's storage.
type StoredImportJob struct {
	Name            string
	State           kmspb.ImportJob_ImportJobState
	ImportMethod    kmspb.ImportJob_ImportMethod
	ProtectionLevel kmspb.ProtectionLevel
	CreateTime      time.Time
	ExpireTime      time.Time
	PublicKeyPEM    string          // wrapping key PEM
	PrivateKey      *rsa.PrivateKey // wrapping key (emulator keeps it to unwrap imports)
}

// generateKeyMaterial creates cryptographic key material for the given algorithm.
// It returns at most one non-nil key value depending on the algorithm family:
//   - symmetricKey for GOOGLE_SYMMETRIC_ENCRYPTION and AES_256_GCM
//   - asymKey for RSA and EC algorithms
//   - hmacKey for HMAC algorithms
func generateKeyMaterial(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (symmetricKey []byte, asymKey *AsymmetricKeyMaterial, hmacKey []byte, err error) {
	switch algorithm {
	// Symmetric encryption (ENCRYPT_DECRYPT purpose)
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION:
		symmetricKey = make([]byte, 32)
		if _, err = rand.Read(symmetricKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate symmetric key: %w", err)
		}
		return symmetricKey, nil, nil, nil

	// RSA signing algorithms
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		bits := rsaBitsFromAlgorithm(algorithm)
		asymKey, err = generateRSAKeyMaterial(bits)
		return nil, asymKey, nil, err

	// RSA decryption algorithms
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		bits := rsaBitsFromAlgorithm(algorithm)
		asymKey, err = generateRSAKeyMaterial(bits)
		return nil, asymKey, nil, err

	// EC signing algorithms
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		asymKey, err = generateECKeyMaterial(elliptic.P256())
		return nil, asymKey, nil, err

	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		asymKey, err = generateECKeyMaterial(elliptic.P384())
		return nil, asymKey, nil, err

	case kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256:
		asymKey, err = generateSecp256k1KeyMaterial()
		return nil, asymKey, nil, err

	// HMAC algorithms
	case kmspb.CryptoKeyVersion_HMAC_SHA1:
		hmacKey = make([]byte, 20)
		if _, err = rand.Read(hmacKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		return nil, nil, hmacKey, nil

	case kmspb.CryptoKeyVersion_HMAC_SHA224:
		hmacKey = make([]byte, 28)
		if _, err = rand.Read(hmacKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		return nil, nil, hmacKey, nil

	case kmspb.CryptoKeyVersion_HMAC_SHA256:
		hmacKey = make([]byte, 32)
		if _, err = rand.Read(hmacKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		return nil, nil, hmacKey, nil

	case kmspb.CryptoKeyVersion_HMAC_SHA384:
		hmacKey = make([]byte, 48)
		if _, err = rand.Read(hmacKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		return nil, nil, hmacKey, nil

	case kmspb.CryptoKeyVersion_HMAC_SHA512:
		hmacKey = make([]byte, 64)
		if _, err = rand.Read(hmacKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate HMAC key: %w", err)
		}
		return nil, nil, hmacKey, nil

	// Raw encryption (AES-128-GCM)
	case kmspb.CryptoKeyVersion_AES_128_GCM:
		symmetricKey = make([]byte, 16)
		if _, err = rand.Read(symmetricKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate AES key: %w", err)
		}
		return symmetricKey, nil, nil, nil

	// Raw encryption (AES-256-GCM)
	case kmspb.CryptoKeyVersion_AES_256_GCM:
		symmetricKey = make([]byte, 32)
		if _, err = rand.Read(symmetricKey); err != nil {
			return nil, nil, nil, fmt.Errorf("generate AES key: %w", err)
		}
		return symmetricKey, nil, nil, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %v", algorithm)
	}
}

// rsaBitsFromAlgorithm returns the RSA key size for a given algorithm.
func rsaBitsFromAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) int {
	name := algorithm.String()
	switch {
	case containsSubstring(name, "2048"):
		return 2048
	case containsSubstring(name, "3072"):
		return 3072
	case containsSubstring(name, "4096"):
		return 4096
	default:
		return 2048
	}
}

// containsSubstring checks if s contains substr (simple helper to avoid importing strings).
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// generateRSAKeyMaterial creates an RSA keypair of the given bit size.
func generateRSAKeyMaterial(bits int) (*AsymmetricKeyMaterial, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return &AsymmetricKeyMaterial{
		PrivateKeyDER: privDER,
		PublicKeyPEM:  string(pubPEM),
	}, nil
}

// generateECKeyMaterial creates an ECDSA keypair on the given curve.
func generateECKeyMaterial(curve elliptic.Curve) (*AsymmetricKeyMaterial, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal EC public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	return &AsymmetricKeyMaterial{
		PrivateKeyDER: privDER,
		PublicKeyPEM:  string(pubPEM),
	}, nil
}
