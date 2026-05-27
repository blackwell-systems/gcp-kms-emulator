package storage

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var (
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1      = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type pkcs8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type sec1ECPrivateKey struct {
	Version    int
	PrivateKey []byte
	NamedCurve asn1.RawValue `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// generateSecp256k1KeyMaterial creates a secp256k1 keypair with PKCS#8 private
// key DER and PKIX SPKI public key PEM.
func generateSecp256k1KeyMaterial() (*AsymmetricKeyMaterial, error) {
	privKey, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}

	privDER, err := marshalSecp256k1PrivateKeyPKCS8(privKey)
	if err != nil {
		return nil, err
	}

	pubPEM, err := marshalSecp256k1PublicKeyPEM(privKey.PubKey())
	if err != nil {
		return nil, err
	}

	return &AsymmetricKeyMaterial{
		PrivateKeyDER: privDER,
		PublicKeyPEM:  pubPEM,
	}, nil
}

func marshalSecp256k1PrivateKeyPKCS8(privKey *secp256k1.PrivateKey) ([]byte, error) {
	oidBytes, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("marshal secp256k1 OID: %w", err)
	}

	ecPriv := sec1ECPrivateKey{
		Version:    1,
		PrivateKey: privKey.Serialize(),
		NamedCurve: asn1.RawValue{FullBytes: oidBytes},
		PublicKey: asn1.BitString{
			Bytes:     privKey.PubKey().SerializeUncompressed(),
			BitLength: len(privKey.PubKey().SerializeUncompressed()) * 8,
		},
	}
	ecPrivDER, err := asn1.Marshal(ecPriv)
	if err != nil {
		return nil, fmt.Errorf("marshal SEC1 EC private key: %w", err)
	}

	algoOIDBytes, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("marshal secp256k1 algorithm OID: %w", err)
	}

	pkcs8Key := pkcs8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: algoOIDBytes,
			},
		},
		PrivateKey: ecPrivDER,
	}

	privDER, err := asn1.Marshal(pkcs8Key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	return privDER, nil
}

func marshalSecp256k1PublicKeyPEM(pubKey *secp256k1.PublicKey) (string, error) {
	oidBytes, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return "", fmt.Errorf("marshal secp256k1 OID: %w", err)
	}

	pubBytes := pubKey.SerializeUncompressed()
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}

	pubDER, err := asn1.Marshal(spki)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(pubPEM), nil
}

func parseSecp256k1PrivateKeyPKCS8(privDER []byte) (*secp256k1.PrivateKey, error) {
	var pkcs8Key pkcs8PrivateKey
	if _, err := asn1.Unmarshal(privDER, &pkcs8Key); err != nil {
		return nil, fmt.Errorf("unmarshal PKCS#8 private key: %w", err)
	}

	if !pkcs8Key.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf("unexpected PKCS#8 algorithm OID: %v", pkcs8Key.Algorithm.Algorithm)
	}

	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(pkcs8Key.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, fmt.Errorf("unmarshal curve OID: %w", err)
	}
	if !curveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("unexpected curve OID: %v", curveOID)
	}

	var ecPriv sec1ECPrivateKey
	if _, err := asn1.Unmarshal(pkcs8Key.PrivateKey, &ecPriv); err != nil {
		return nil, fmt.Errorf("unmarshal SEC1 EC private key: %w", err)
	}

	return secp256k1.PrivKeyFromBytes(ecPriv.PrivateKey), nil
}

func parseSecp256k1PublicKeyPEM(pemStr string) (*secp256k1.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM public key")
	}

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal SPKI public key: %w", err)
	}

	if !spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf("unexpected SPKI algorithm OID: %v", spki.Algorithm.Algorithm)
	}

	pubKey, err := secp256k1.ParsePubKey(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 public key: %w", err)
	}
	return pubKey, nil
}

func signSecp256k1(privateKeyDER, digest []byte) ([]byte, error) {
	privKey, err := parseSecp256k1PrivateKeyPKCS8(privateKeyDER)
	if err != nil {
		return nil, err
	}

	sig := ecdsa.Sign(privKey, digest)
	return sig.Serialize(), nil
}

// VerifySecp256k1ASN1 verifies a DER-encoded ECDSA signature against a PEM-encoded
// secp256k1 public key and SHA-256 digest.
func VerifySecp256k1ASN1(publicKeyPEM string, digest, signature []byte) error {
	pubKey, err := parseSecp256k1PublicKeyPEM(publicKeyPEM)
	if err != nil {
		return err
	}

	sig, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return fmt.Errorf("parse DER signature: %w", err)
	}

	if !sig.Verify(digest, pubKey) {
		return fmt.Errorf("secp256k1 signature verification failed")
	}
	return nil
}
