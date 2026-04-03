// Package server implements the gRPC server for the Google Cloud KMS API.
//
// This package provides the gRPC service implementation that handles KMS requests
// and delegates to the storage layer. It implements the KeyManagementService
// interface from cloud.google.com/go/kms/apiv1/kmspb.
//
// # Error Handling
//
// All methods validate input parameters and return appropriate gRPC status codes:
//   - InvalidArgument: Missing required fields
//   - NotFound: Requested resource doesn't exist
//   - AlreadyExists: Resource already exists
//   - FailedPrecondition: Invalid state transition
//   - Internal: Unexpected errors
//
// # Supported Methods
//
// KeyRing Management: CreateKeyRing, GetKeyRing, ListKeyRings
//
// CryptoKey Management: CreateCryptoKey, GetCryptoKey, ListCryptoKeys, UpdateCryptoKey
//
// CryptoKeyVersion Management: CreateCryptoKeyVersion, GetCryptoKeyVersion,
// ListCryptoKeyVersions, UpdateCryptoKeyVersion, UpdateCryptoKeyPrimaryVersion,
// DestroyCryptoKeyVersion
//
// Encryption Operations: Encrypt, Decrypt
//
// # Usage
//
//	grpcServer := grpc.NewServer()
//	kmsServer := server.NewServer()
//	kmspb.RegisterKeyManagementServiceServer(grpcServer, kmsServer)
package server

import (
	"context"
	"errors"
	"fmt"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	emulatorauth "github.com/blackwell-systems/gcp-emulator-auth"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/authz"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/storage"
)

// requireField returns an InvalidArgument error if value is empty.
func requireField(value, name string) error {
	if value == "" {
		return status.Errorf(codes.InvalidArgument, "%s is required", name)
	}
	return nil
}

// storageErr maps typed storage errors to gRPC status codes.
func storageErr(err error) error {
	var notFound *storage.ErrNotFound
	var alreadyExists *storage.ErrAlreadyExists
	var precondition *storage.ErrFailedPrecondition
	switch {
	case errors.As(err, &notFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &alreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.As(err, &precondition):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// Server implements the KMS KeyManagementService
type Server struct {
	kmspb.UnimplementedKeyManagementServiceServer
	storage   *storage.Storage
	iamClient *emulatorauth.Client
	iamMode   emulatorauth.AuthMode
}

// NewServer creates a new KMS server
func NewServer() (*Server, error) {
	s := &Server{
		storage: storage.NewStorage(),
	}

	// Load IAM configuration from environment
	config := emulatorauth.LoadFromEnv()
	s.iamMode = config.Mode

	// Connect to IAM emulator if enabled
	if config.Mode.IsEnabled() {
		client, err := emulatorauth.NewClient(config.Host, config.Mode, "gcp-kms-emulator")
		if err != nil {
			return nil, fmt.Errorf("failed to connect to IAM emulator: %w", err)
		}
		s.iamClient = client
	}

	return s, nil
}

// checkPermission checks if the principal has permission to perform the operation
func (s *Server) checkPermission(ctx context.Context, operation string, resource string) error {
	// If IAM is disabled, allow all operations
	if s.iamClient == nil {
		return nil
	}

	// Extract principal from incoming context
	principal := emulatorauth.ExtractPrincipalFromContext(ctx)

	// Get permission for operation
	permCheck, ok := authz.GetPermission(operation)
	if !ok {
		// Operation not in permission map - allow (shouldn't happen)
		return nil
	}

	// Check permission
	allowed, err := s.iamClient.CheckPermission(ctx, principal, resource, permCheck.Permission)
	if err != nil {
		return status.Errorf(codes.Internal, "IAM check failed: %v", err)
	}

	if !allowed {
		return status.Error(codes.PermissionDenied, "Permission denied")
	}

	return nil
}

// CreateKeyRing creates a new keyring
func (s *Server) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := requireField(req.KeyRingId, "key_ring_id"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "CreateKeyRing", authz.NormalizeParentForCreate(req.Parent)); err != nil {
		return nil, err
	}

	name := fmt.Sprintf("%s/keyRings/%s", req.Parent, req.KeyRingId)
	keyring, err := s.storage.CreateKeyRing(name)
	if err != nil {
		return nil, storageErr(err)
	}
	return keyring, nil
}

// GetKeyRing retrieves a keyring
func (s *Server) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GetKeyRing", authz.NormalizeKeyRingResource(req.Name)); err != nil {
		return nil, err
	}

	keyring, err := s.storage.GetKeyRing(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}
	return keyring, nil
}

// ListKeyRings lists keyrings in a location
func (s *Server) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "ListKeyRings", authz.NormalizeParentForCreate(req.Parent)); err != nil {
		return nil, err
	}

	keyrings, err := s.storage.ListKeyRings(req.Parent)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.ListKeyRingsResponse{
		KeyRings:      keyrings,
		NextPageToken: "",
		TotalSize:     int32(len(keyrings)),
	}, nil
}

// CreateCryptoKey creates a new crypto key
func (s *Server) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := requireField(req.CryptoKeyId, "crypto_key_id"); err != nil {
		return nil, err
	}
	if req.CryptoKey == nil {
		return nil, status.Error(codes.InvalidArgument, "crypto_key is required")
	}
	if err := s.checkPermission(ctx, "CreateCryptoKey", authz.NormalizeKeyRingResource(req.Parent)); err != nil {
		return nil, err
	}

	purpose := req.CryptoKey.Purpose
	if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "crypto_key.purpose is required")
	}

	cryptoKey, err := s.storage.CreateCryptoKey(
		req.Parent, req.CryptoKeyId, purpose,
		req.CryptoKey.VersionTemplate, req.CryptoKey.Labels,
	)
	if err != nil {
		return nil, storageErr(err)
	}
	return cryptoKey, nil
}

// GetCryptoKey retrieves a crypto key
func (s *Server) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GetCryptoKey", authz.NormalizeCryptoKeyResource(req.Name)); err != nil {
		return nil, err
	}

	cryptoKey, err := s.storage.GetCryptoKey(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}
	return cryptoKey, nil
}

// Encrypt encrypts data using a crypto key
func (s *Server) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}
	if err := verifyCRC32C(req.Plaintext, req.PlaintextCrc32C); err != nil {
		return nil, err
	}
	if err := verifyCRC32C(req.AdditionalAuthenticatedData, req.AdditionalAuthenticatedDataCrc32C); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "Encrypt", authz.NormalizeCryptoKeyResource(req.Name)); err != nil {
		return nil, err
	}

	ciphertext, versionName, err := s.storage.Encrypt(req.Name, req.Plaintext, req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.EncryptResponse{
		Name:                    versionName,
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        crc32cValue(ciphertext),
		VerifiedPlaintextCrc32C: req.PlaintextCrc32C != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: req.AdditionalAuthenticatedDataCrc32C != nil,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// Decrypt decrypts data using a crypto key
func (s *Server) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}
	if err := verifyCRC32C(req.Ciphertext, req.CiphertextCrc32C); err != nil {
		return nil, err
	}
	if err := verifyCRC32C(req.AdditionalAuthenticatedData, req.AdditionalAuthenticatedDataCrc32C); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "Decrypt", authz.NormalizeCryptoKeyResource(req.Name)); err != nil {
		return nil, err
	}

	plaintext, usedVersionName, err := s.storage.Decrypt(req.Name, req.Ciphertext, req.AdditionalAuthenticatedData)
	if err != nil {
		return nil, storageErr(err)
	}
	// Determine UsedPrimary: fetch the key to compare with primary version name
	cryptoKey, getErr := s.storage.GetCryptoKey(req.Name)
	usedPrimary := getErr == nil && cryptoKey.Primary != nil && cryptoKey.Primary.Name == usedVersionName
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: crc32cValue(plaintext),
		UsedPrimary:     usedPrimary,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

func (s *Server) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "ListCryptoKeys", authz.NormalizeKeyRingResource(req.Parent)); err != nil {
		return nil, err
	}

	cryptoKeys, err := s.storage.ListCryptoKeys(req.Parent)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.ListCryptoKeysResponse{
		CryptoKeys:    cryptoKeys,
		NextPageToken: "",
		TotalSize:     int32(len(cryptoKeys)),
	}, nil
}

func (s *Server) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "ListCryptoKeyVersions", authz.NormalizeCryptoKeyResource(req.Parent)); err != nil {
		return nil, err
	}

	versions, err := s.storage.ListCryptoKeyVersions(req.Parent)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: versions,
		NextPageToken:     "",
		TotalSize:         int32(len(versions)),
	}, nil
}

func (s *Server) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GetCryptoKeyVersion", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	version, err := s.storage.GetCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}
	return version, nil
}

func (s *Server) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "CreateCryptoKeyVersion", authz.NormalizeCryptoKeyResource(req.Parent)); err != nil {
		return nil, err
	}

	version, err := s.storage.CreateCryptoKeyVersion(req.Parent, req.CryptoKeyVersion)
	if err != nil {
		return nil, storageErr(err)
	}
	return version, nil
}

func (s *Server) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if req.CryptoKey == nil || req.CryptoKey.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key.name is required")
	}
	if req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0 {
		return nil, status.Error(codes.InvalidArgument, "update_mask is required")
	}
	if err := s.checkPermission(ctx, "UpdateCryptoKey", authz.NormalizeCryptoKeyResource(req.CryptoKey.Name)); err != nil {
		return nil, err
	}

	cryptoKey, err := s.storage.UpdateCryptoKey(req.CryptoKey.Name, req.CryptoKey, req.UpdateMask)
	if err != nil {
		return nil, storageErr(err)
	}
	return cryptoKey, nil
}

func (s *Server) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if req.CryptoKeyVersion == nil || req.CryptoKeyVersion.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_version.name is required")
	}
	if err := s.checkPermission(ctx, "UpdateCryptoKeyVersion", authz.NormalizeCryptoKeyVersionResource(req.CryptoKeyVersion.Name)); err != nil {
		return nil, err
	}

	version, err := s.storage.UpdateCryptoKeyVersion(req.CryptoKeyVersion.Name, req.CryptoKeyVersion.State, req.UpdateMask)
	if err != nil {
		return nil, storageErr(err)
	}
	return version, nil
}

func (s *Server) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := requireField(req.CryptoKeyVersionId, "crypto_key_version_id"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "UpdateCryptoKeyPrimaryVersion", authz.NormalizeCryptoKeyResource(req.Name)); err != nil {
		return nil, err
	}

	versionName := fmt.Sprintf("%s/cryptoKeyVersions/%s", req.Name, req.CryptoKeyVersionId)
	cryptoKey, err := s.storage.UpdateCryptoKeyPrimaryVersion(req.Name, versionName)
	if err != nil {
		return nil, storageErr(err)
	}
	return cryptoKey, nil
}

func (s *Server) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "DestroyCryptoKeyVersion", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	version, err := s.storage.DestroyCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}
	return version, nil
}

func (s *Server) RestoreCryptoKeyVersion(ctx context.Context, req *kmspb.RestoreCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "RestoreCryptoKeyVersion", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	version, err := s.storage.RestoreCryptoKeyVersion(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}
	return version, nil
}

// Decapsulate is a stub for KEM decapsulation (not yet supported).
// TODO: Implement KEM support when needed.
func (s *Server) Decapsulate(ctx context.Context, req *kmspb.DecapsulateRequest) (*kmspb.DecapsulateResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "KEM not yet supported")
}
