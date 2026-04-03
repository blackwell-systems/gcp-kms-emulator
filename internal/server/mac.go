package server

import (
	"context"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/authz"
)

// MacSign computes an HMAC tag for request data using the specified key version.
func (s *Server) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}
	if err := s.checkPermission(ctx, "MacSign", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	mac, err := s.storage.MacSign(req.Name, req.Data)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.MacSignResponse{
		Name:               req.Name,
		Mac:                mac,
		MacCrc32C:          crc32cValue(mac),
		VerifiedDataCrc32C: req.DataCrc32C != nil,
		ProtectionLevel:    kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}

// MacVerify verifies an HMAC tag against request data using the specified key version.
func (s *Server) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	if err := requireField(req.Name, "name"); err != nil {
		return nil, err
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}
	if len(req.Mac) == 0 {
		return nil, status.Error(codes.InvalidArgument, "mac is required")
	}
	if err := s.checkPermission(ctx, "MacVerify", authz.NormalizeCryptoKeyVersionResource(req.Name)); err != nil {
		return nil, err
	}

	success, err := s.storage.MacVerify(req.Name, req.Data, req.Mac)
	if err != nil {
		return nil, storageErr(err)
	}
	return &kmspb.MacVerifyResponse{
		Name:                     req.Name,
		Success:                  success,
		VerifiedDataCrc32C:       req.DataCrc32C != nil,
		VerifiedMacCrc32C:        req.MacCrc32C != nil,
		VerifiedSuccessIntegrity: true,
		ProtectionLevel:          kmspb.ProtectionLevel_SOFTWARE,
	}, nil
}
