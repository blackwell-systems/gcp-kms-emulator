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
	if req.Digest == nil {
		return nil, status.Error(codes.InvalidArgument, "digest is required")
	}
	if err := s.checkPermission(ctx, "AsymmetricSign", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

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

	sig, err := s.storage.AsymmetricSign(req.Name, digestBytes, digestType)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.AsymmetricSignResponse{
		Signature: sig,
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

	pt, err := s.storage.AsymmetricDecrypt(req.Name, req.Ciphertext)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.AsymmetricDecryptResponse{
		Plaintext: pt,
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
		Pem:       pemStr,
		Algorithm: kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(alg),
	}, nil
}
