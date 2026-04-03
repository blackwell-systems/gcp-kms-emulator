package gcp_kms_emulator

import (
	"net/http"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/gateway"
)

// NewGatewayHandler returns an http.Handler that proxies REST requests to the
// KMS gRPC service at grpcAddr. Used by gcp-emulator to mount the KMS REST API
// onto a unified HTTP server.
func NewGatewayHandler(grpcAddr string) (http.Handler, error) {
	srv, err := gateway.NewServer(grpcAddr)
	if err != nil {
		return nil, err
	}
	return srv.Handler(), nil
}
