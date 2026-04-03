// Package kmsv1 provides grpc-gateway handler registration for the
// Google Cloud KMS v1 API.
//
// This file re-exports gRPC service interfaces and request/response types
// from cloud.google.com/go/kms/apiv1/kmspb so that the generated gateway
// file (service.pb.gw.go) compiles without also generating pb.go.
package kmsv1

import (
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
)

// gRPC service interfaces and constructors.
type KeyManagementServiceClient = kmspb.KeyManagementServiceClient
type KeyManagementServiceServer = kmspb.KeyManagementServiceServer

func NewKeyManagementServiceClient(cc grpc.ClientConnInterface) KeyManagementServiceClient {
	return kmspb.NewKeyManagementServiceClient(cc)
}

// Request types used by the gateway handlers.
type AsymmetricDecryptRequest = kmspb.AsymmetricDecryptRequest
type AsymmetricSignRequest = kmspb.AsymmetricSignRequest
type CreateCryptoKeyRequest = kmspb.CreateCryptoKeyRequest
type CreateCryptoKeyVersionRequest = kmspb.CreateCryptoKeyVersionRequest
type CreateImportJobRequest = kmspb.CreateImportJobRequest
type CreateKeyRingRequest = kmspb.CreateKeyRingRequest
type DecapsulateRequest = kmspb.DecapsulateRequest
type DecryptRequest = kmspb.DecryptRequest
type DestroyCryptoKeyVersionRequest = kmspb.DestroyCryptoKeyVersionRequest
type EncryptRequest = kmspb.EncryptRequest
type GenerateRandomBytesRequest = kmspb.GenerateRandomBytesRequest
type GetCryptoKeyRequest = kmspb.GetCryptoKeyRequest
type GetCryptoKeyVersionRequest = kmspb.GetCryptoKeyVersionRequest
type GetImportJobRequest = kmspb.GetImportJobRequest
type GetKeyRingRequest = kmspb.GetKeyRingRequest
type GetPublicKeyRequest = kmspb.GetPublicKeyRequest
type ImportCryptoKeyVersionRequest = kmspb.ImportCryptoKeyVersionRequest
type ListCryptoKeysRequest = kmspb.ListCryptoKeysRequest
type ListCryptoKeyVersionsRequest = kmspb.ListCryptoKeyVersionsRequest
type ListImportJobsRequest = kmspb.ListImportJobsRequest
type ListKeyRingsRequest = kmspb.ListKeyRingsRequest
type MacSignRequest = kmspb.MacSignRequest
type MacVerifyRequest = kmspb.MacVerifyRequest
type RawDecryptRequest = kmspb.RawDecryptRequest
type RawEncryptRequest = kmspb.RawEncryptRequest
type RestoreCryptoKeyVersionRequest = kmspb.RestoreCryptoKeyVersionRequest
type UpdateCryptoKeyPrimaryVersionRequest = kmspb.UpdateCryptoKeyPrimaryVersionRequest
type UpdateCryptoKeyRequest = kmspb.UpdateCryptoKeyRequest
type UpdateCryptoKeyVersionRequest = kmspb.UpdateCryptoKeyVersionRequest
