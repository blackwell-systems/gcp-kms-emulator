package server

import (
	"context"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/authz"
)

// RawEncrypt performs AES-GCM encryption on plaintext using a specific key version,
// returning the ciphertext, initialization vector, and tag length separately
// (without envelope wrapping).
func (s *Server) RawEncrypt(ctx context.Context, req *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}
	if err := s.checkPermission(ctx, "RawEncrypt", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	ct, iv, tagLen, err := s.storage.RawEncrypt(req.Name, req.Plaintext, req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.RawEncryptResponse{
		Ciphertext:           ct,
		InitializationVector: iv,
		TagLength:            tagLen,
	}, nil
}

// RawDecrypt performs AES-GCM decryption on ciphertext using a specific key version,
// without envelope wrapping.
func (s *Server) RawDecrypt(ctx context.Context, req *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}
	if len(req.InitializationVector) == 0 {
		return nil, status.Error(codes.InvalidArgument, "initialization_vector is required")
	}
	if err := s.checkPermission(ctx, "RawDecrypt", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	pt, err := s.storage.RawDecrypt(req.Name, req.Ciphertext, req.InitializationVector, req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.RawDecryptResponse{
		Plaintext: pt,
	}, nil
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func (s *Server) GenerateRandomBytes(ctx context.Context, req *kmspb.GenerateRandomBytesRequest) (*kmspb.GenerateRandomBytesResponse, error) {
	if err := requireField(req.Location, "location"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GenerateRandomBytes", req.Location); err != nil {
		return nil, err
	}

	data, err := s.storage.GenerateRandomBytes(req.LengthBytes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	return &kmspb.GenerateRandomBytesResponse{
		Data: data,
	}, nil
}
