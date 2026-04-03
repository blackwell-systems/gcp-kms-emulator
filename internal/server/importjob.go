package server

import (
	"context"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/authz"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/storage"
)

// CreateImportJob creates a new import job in a keyring.
func (s *Server) CreateImportJob(ctx context.Context, req *kmspb.CreateImportJobRequest) (*kmspb.ImportJob, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := requireField(req.ImportJobId, "import_job_id"); err != nil {
		return nil, err
	}
	if req.ImportJob == nil {
		return nil, status.Error(codes.InvalidArgument, "import_job is required")
	}
	if err := s.checkPermission(ctx, "CreateImportJob", authz.NormalizeKeyRingResource(req.Parent)); err != nil {
		return nil, err
	}

	stored, err := s.storage.CreateImportJob(
		req.Parent,
		req.ImportJobId,
		int32(req.ImportJob.ImportMethod),
		int32(req.ImportJob.ProtectionLevel),
	)
	if err != nil {
		return nil, storageErr(err)
	}

	return storedImportJobToProto(stored), nil
}

// GetImportJob retrieves an import job by name.
func (s *Server) GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest) (*kmspb.ImportJob, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "GetImportJob", authz.NormalizeKeyRingResource(req.Name)); err != nil {
		return nil, err
	}

	stored, err := s.storage.GetImportJob(req.Name)
	if err != nil {
		return nil, storageErr(err)
	}

	return storedImportJobToProto(stored), nil
}

// ListImportJobs lists import jobs in a keyring.
func (s *Server) ListImportJobs(ctx context.Context, req *kmspb.ListImportJobsRequest) (*kmspb.ListImportJobsResponse, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "ListImportJobs", authz.NormalizeKeyRingResource(req.Parent)); err != nil {
		return nil, err
	}

	stored, err := s.storage.ListImportJobs(req.Parent)
	if err != nil {
		return nil, storageErr(err)
	}

	var importJobs []*kmspb.ImportJob
	for _, ij := range stored {
		importJobs = append(importJobs, storedImportJobToProto(ij))
	}

	return &kmspb.ListImportJobsResponse{
		ImportJobs:    importJobs,
		NextPageToken: "",
		TotalSize:     int32(len(importJobs)),
	}, nil
}

// ImportCryptoKeyVersion imports a wrapped key into a crypto key version.
func (s *Server) ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := requireField(req.Parent, "parent"); err != nil {
		return nil, err
	}
	if err := requireField(req.ImportJob, "import_job"); err != nil {
		return nil, err
	}
	if err := s.checkPermission(ctx, "ImportCryptoKeyVersion", authz.NormalizeCryptoKeyResource(req.Parent)); err != nil {
		return nil, err
	}

	if req.Algorithm == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	// Extract wrapped key: prefer the direct WrappedKey field, fall back to legacy oneof
	wrappedKey := req.GetWrappedKey()
	if len(wrappedKey) == 0 {
		wrappedKey = req.GetRsaAesWrappedKey()
	}
	if len(wrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key or rsa_aes_wrapped_key is required")
	}

	stored, err := s.storage.ImportCryptoKeyVersion(
		req.Parent,
		int32(req.Algorithm),
		req.ImportJob,
		wrappedKey,
	)
	if err != nil {
		return nil, storageErr(err)
	}

	return &kmspb.CryptoKeyVersion{
		Name:       stored.Name,
		State:      stored.State,
		CreateTime: timestamppb.New(stored.CreateTime),
		Algorithm:  stored.Algorithm,
	}, nil
}

// storedImportJobToProto converts a StoredImportJob to the proto representation.
func storedImportJobToProto(stored *storage.StoredImportJob) *kmspb.ImportJob {
	return &kmspb.ImportJob{
		Name:            stored.Name,
		ImportMethod:    stored.ImportMethod,
		ProtectionLevel: stored.ProtectionLevel,
		State:           stored.State,
		CreateTime:      timestamppb.New(stored.CreateTime),
		ExpireTime:      timestamppb.New(stored.ExpireTime),
		PublicKey: &kmspb.ImportJob_WrappingPublicKey{
			Pem: stored.PublicKeyPEM,
		},
	}
}
