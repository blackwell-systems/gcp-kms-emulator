// Package gateway provides HTTP/REST gateway access to the gRPC KMS service
// using grpc-gateway v2 to transcode HTTP/JSON ↔ gRPC.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	kmsv1 "github.com/blackwell-systems/gcp-kms-emulator/internal/gen/google/cloud/kms/v1"
)

// googleErrorHandler writes errors in the shape the Cloud KMS REST API uses,
// {"error": {"code": <HTTP status>, "message": ..., "status": "INVALID_ARGUMENT"}},
// so REST clients written against Google parse emulator errors the same way.
// Malformed request bodies become a clean INVALID_ARGUMENT instead of leaking
// Go parse internals.
func googleErrorHandler(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	st := status.Convert(err)
	msg := st.Message()
	c := st.Code()
	if strings.HasPrefix(msg, "proto:") ||
		strings.Contains(msg, "invalid character") ||
		strings.Contains(msg, "unexpected end of JSON") {
		c, msg = codes.InvalidArgument, "request body is not valid JSON"
	}
	httpStatus := runtime.HTTPStatusFromCode(c)
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    httpStatus,
			"message": msg,
			"status":  rpccode.Code(c).String(),
		},
	})
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpStatus)
	_, _ = w.Write(body)
}

// Server represents the REST gateway server.
type Server struct {
	mux     *runtime.ServeMux
	httpSrv *http.Server
	conn    *grpc.ClientConn
}

// NewServer creates a new REST gateway server that proxies to a gRPC server.
func NewServer(grpcAddr string) (*Server, error) {
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC server: %w", err)
	}

	mux := runtime.NewServeMux(runtime.WithErrorHandler(googleErrorHandler))
	ctx := context.Background()

	if err := kmsv1.RegisterKeyManagementServiceHandlerClient(ctx, mux, kmsv1.NewKeyManagementServiceClient(conn)); err != nil {
		conn.Close()
		return nil, err
	}

	// Health endpoints.
	healthHandler := func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
	_ = mux.HandlePath("GET", "/healthz", healthHandler)
	_ = mux.HandlePath("GET", "/readyz", healthHandler)
	_ = mux.HandlePath("GET", "/health", healthHandler)

	return &Server{mux: mux, conn: conn}, nil
}

// Handler returns the HTTP handler for this gateway, suitable for mounting
// into a parent mux (e.g. the unified gcp-emulator gateway).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Start starts the REST gateway server on the specified address.
func (s *Server) Start(ctx context.Context, addr string) error {
	s.httpSrv = &http.Server{Addr: addr, Handler: s.mux}
	return s.httpSrv.ListenAndServe()
}

// Stop gracefully stops the REST gateway server.
func (s *Server) Stop(ctx context.Context) error {
	if s.conn != nil {
		s.conn.Close()
	}
	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	return nil
}
