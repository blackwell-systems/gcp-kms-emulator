// Package server implements the KMS gRPC server
package server

import (
	"context"
	"fmt"
	"strings"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/storage"
)

// Server implements the KMS KeyManagementService
type Server struct {
	kmspb.UnimplementedKeyManagementServiceServer
	storage *storage.Storage
}

// NewServer creates a new KMS server
func NewServer() *Server {
	return &Server{
		storage: storage.NewStorage(),
	}
}

// CreateKeyRing creates a new keyring
func (s *Server) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}
	if req.KeyRingId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_ring_id is required")
	}

	name := fmt.Sprintf("%s/keyRings/%s", req.Parent, req.KeyRingId)
	keyring, err := s.storage.CreateKeyRing(name)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return keyring, nil
}

// GetKeyRing retrieves a keyring
func (s *Server) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	keyring, err := s.storage.GetKeyRing(req.Name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return keyring, nil
}

// ListKeyRings lists keyrings in a location
func (s *Server) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}

	keyrings, err := s.storage.ListKeyRings(req.Parent)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &kmspb.ListKeyRingsResponse{
		KeyRings:      keyrings,
		NextPageToken: "",
		TotalSize:     int32(len(keyrings)),
	}, nil
}

// CreateCryptoKey creates a new crypto key
func (s *Server) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}
	if req.CryptoKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_id is required")
	}
	if req.CryptoKey == nil {
		return nil, status.Error(codes.InvalidArgument, "crypto_key is required")
	}

	purpose := req.CryptoKey.Purpose
	if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
		purpose = kmspb.CryptoKey_ENCRYPT_DECRYPT
	}

	cryptoKey, err := s.storage.CreateCryptoKey(
		req.Parent,
		req.CryptoKeyId,
		purpose,
		req.CryptoKey.VersionTemplate,
		req.CryptoKey.Labels,
	)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return cryptoKey, nil
}

// GetCryptoKey retrieves a crypto key
func (s *Server) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	cryptoKey, err := s.storage.GetCryptoKey(req.Name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return cryptoKey, nil
}

// Encrypt encrypts data using a crypto key
func (s *Server) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	ciphertext, err := s.storage.Encrypt(req.Name, req.Plaintext)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &kmspb.EncryptResponse{
		Name:             req.Name,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: nil, // Not implementing CRC32C for simplicity
	}, nil
}

// Decrypt decrypts data using a crypto key
func (s *Server) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	plaintext, err := s.storage.Decrypt(req.Name, req.Ciphertext)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: nil, // Not implementing CRC32C for simplicity
	}, nil
}

func (s *Server) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}

	cryptoKeys, err := s.storage.ListCryptoKeys(req.Parent)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &kmspb.ListCryptoKeysResponse{
		CryptoKeys:    cryptoKeys,
		NextPageToken: "",
		TotalSize:     int32(len(cryptoKeys)),
	}, nil
}

func (s *Server) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}

	versions, err := s.storage.ListCryptoKeyVersions(req.Parent)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: versions,
		NextPageToken:     "",
		TotalSize:         int32(len(versions)),
	}, nil
}

func (s *Server) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	version, err := s.storage.GetCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return version, nil
}

func (s *Server) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if req.Parent == "" {
		return nil, status.Error(codes.InvalidArgument, "parent is required")
	}

	version, err := s.storage.CreateCryptoKeyVersion(req.Parent)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return version, nil
}

func (s *Server) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if req.CryptoKey == nil || req.CryptoKey.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key.name is required")
	}

	cryptoKey, err := s.storage.UpdateCryptoKey(req.CryptoKey.Name, req.CryptoKey.Labels)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return cryptoKey, nil
}

func (s *Server) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if req.CryptoKeyVersion == nil || req.CryptoKeyVersion.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_version.name is required")
	}

	if req.CryptoKeyVersion.State == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_STATE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_version.state is required")
	}

	version, err := s.storage.UpdateCryptoKeyVersion(req.CryptoKeyVersion.Name, req.CryptoKeyVersion.State)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return version, nil
}

func (s *Server) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.CryptoKeyVersionId == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_version_id is required")
	}

	versionName := fmt.Sprintf("%s/cryptoKeyVersions/%s", req.Name, req.CryptoKeyVersionId)
	cryptoKey, err := s.storage.UpdateCryptoKeyPrimaryVersion(req.Name, versionName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if strings.Contains(err.Error(), "not enabled") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return cryptoKey, nil
}

func (s *Server) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	version, err := s.storage.DestroyCryptoKeyVersion(req.Name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if strings.Contains(err.Error(), "already destroyed") {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return version, nil
}

func (s *Server) RestoreCryptoKeyVersion(ctx context.Context, req *kmspb.RestoreCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return nil, status.Error(codes.Unimplemented, "RestoreCryptoKeyVersion not implemented yet")
}

func (s *Server) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	return nil, status.Error(codes.Unimplemented, "GetPublicKey not implemented yet")
}

func (s *Server) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AsymmetricSign not implemented yet")
}

func (s *Server) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AsymmetricDecrypt not implemented yet")
}

func (s *Server) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	return nil, status.Error(codes.Unimplemented, "MacSign not implemented yet")
}

func (s *Server) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "MacVerify not implemented yet")
}

func (s *Server) GenerateRandomBytes(ctx context.Context, req *kmspb.GenerateRandomBytesRequest) (*kmspb.GenerateRandomBytesResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GenerateRandomBytes not implemented yet")
}

func (s *Server) ListImportJobs(ctx context.Context, req *kmspb.ListImportJobsRequest) (*kmspb.ListImportJobsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListImportJobs not implemented yet")
}

func (s *Server) GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest) (*kmspb.ImportJob, error) {
	return nil, status.Error(codes.Unimplemented, "GetImportJob not implemented yet")
}

func (s *Server) CreateImportJob(ctx context.Context, req *kmspb.CreateImportJobRequest) (*kmspb.ImportJob, error) {
	return nil, status.Error(codes.Unimplemented, "CreateImportJob not implemented yet")
}

func (s *Server) ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return nil, status.Error(codes.Unimplemented, "ImportCryptoKeyVersion not implemented yet")
}

func (s *Server) RawEncrypt(ctx context.Context, req *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RawEncrypt not implemented yet")
}

func (s *Server) RawDecrypt(ctx context.Context, req *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RawDecrypt not implemented yet")
}

func (s *Server) Decapsulate(ctx context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Decapsulate not implemented yet")
}
