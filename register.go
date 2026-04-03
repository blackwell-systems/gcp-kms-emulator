// Package gcp_kms_emulator provides the composition entry point for the GCP KMS Emulator.
//
// Register wires the KMS gRPC service onto an existing grpc.Server,
// enabling use within the unified gcp-emulator or any custom composition layer.
// For standalone use, see cmd/server, cmd/server-rest, or cmd/server-dual.
package gcp_kms_emulator

import (
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
)

// Option configures the KMS server at registration time.
type Option func(*options)

type options struct{}

// Register adds the KMS gRPC service to grpcSrv.
// IAM enforcement is configured via the IAM_MODE and IAM_EMULATOR_HOST
// environment variables (same as the standalone binary).
// It does not start a listener — the caller owns the grpc.Server lifecycle.
func Register(grpcSrv *grpc.Server, opts ...Option) error {
	srv, err := server.NewServer()
	if err != nil {
		return err
	}
	kmspb.RegisterKeyManagementServiceServer(grpcSrv, srv)
	reflection.Register(grpcSrv)
	return nil
}
