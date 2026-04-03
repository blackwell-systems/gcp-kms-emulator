// asymmetric.go implements the gRPC server handlers for asymmetric crypto
// operations: AsymmetricSign, AsymmetricDecrypt, and GetPublicKey.
package server

import (
	"context"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/authz"
)

// AsymmetricSign signs data using an asymmetric key version.
func (s *Server) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if req.Digest == nil && len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "either digest or data is required")
	}
	if err := s.checkPermission(ctx, "AsymmetricSign", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	var sig []byte
	var verifiedDigestCrc32C bool
	var verifiedDataCrc32C bool

	if req.Digest != nil {
		// Extract digest bytes and type from the oneof field
		var digestBytes []byte
		var digestType string
		switch d := req.Digest.Digest.(type) {
		case *kmspb.Digest_Sha256:
			digestBytes = d.Sha256
			digestType = "SHA256"
		case *kmspb.Digest_Sha384:
			digestBytes = d.Sha384
			digestType = "SHA384"
		case *kmspb.Digest_Sha512:
			digestBytes = d.Sha512
			digestType = "SHA512"
		default:
			return nil, status.Error(codes.InvalidArgument, "unsupported digest type")
		}

		// Verify CRC32C of the digest if provided
		if err := verifyCRC32C(digestBytes, req.DigestCrc32C); err != nil {
			return nil, err
		}
		verifiedDigestCrc32C = req.DigestCrc32C != nil

		var err error
		sig, err = s.storage.AsymmetricSign(req.Name, digestBytes, digestType, nil)
		if err != nil {
			return nil, storageErr(err)
		}
	} else {
		// Use raw data field — verify CRC32C if provided
		if err := verifyCRC32C(req.Data, req.DataCrc32C); err != nil {
			return nil, err
		}
		verifiedDataCrc32C = req.DataCrc32C != nil

		var err error
		sig, err = s.storage.AsymmetricSign(req.Name, nil, "", req.Data)
		if err != nil {
			return nil, storageErr(err)
		}
	}

	return &kmspb.AsymmetricSignResponse{
		Name:                 req.Name,
		Signature:            sig,
		SignatureCrc32C:      crc32cValue(sig),
		VerifiedDigestCrc32C: verifiedDigestCrc32C,
		VerifiedDataCrc32C:   verifiedDataCrc32C,
		ProtectionLevel:      kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// AsymmetricDecrypt decrypts data using an asymmetric key version.
func (s *Server) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}
	if err := s.checkPermission(ctx, "AsymmetricDecrypt", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	if err := verifyCRC32C(req.Ciphertext, req.CiphertextCrc32C); err != nil {
		return nil, err
	}

	pt, err := s.storage.AsymmetricDecrypt(req.Name, req.Ciphertext)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.AsymmetricDecryptResponse{
		Plaintext:                pt,
		PlaintextCrc32C:          crc32cValue(pt),
		VerifiedCiphertextCrc32C: req.CiphertextCrc32C != nil,
		ProtectionLevel:          kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// GetPublicKey retrieves the public key for an asymmetric key version.
func (s *Server) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GetPublicKey", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	pemStr, alg, err := s.storage.GetPublicKey(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.PublicKey{
		Name:            req.Name,
		Pem:             pemStr,
		Algorithm:       kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(alg),
		PemCrc32C:       crc32cValue([]byte(pemStr)),
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}
