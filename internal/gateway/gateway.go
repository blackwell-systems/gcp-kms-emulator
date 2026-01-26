// Package gateway provides HTTP/REST API access to the gRPC KMS service
package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Server represents the REST gateway server
type Server struct {
	grpcClient kmspb.KeyManagementServiceClient
	httpServer *http.Server
	conn       *grpc.ClientConn
}

// NewServer creates a new REST gateway server that proxies to a gRPC server
func NewServer(grpcAddr string) *Server {
	conn, err := grpc.NewClient(
		grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to dial gRPC server: %v", err))
	}

	return &Server{
		grpcClient: kmspb.NewKeyManagementServiceClient(conn),
		conn:       conn,
	}
}

// Start starts the REST gateway server on the specified address
func (s *Server) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()

	// Register routes matching GCP's REST API
	mux.HandleFunc("/v1/", s.handleRequest)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy"}`)
	})

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s.httpServer.ListenAndServe()
}

// Stop gracefully stops the REST gateway server
func (s *Server) Stop(ctx context.Context) error {
	if s.conn != nil {
		s.conn.Close()
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleRequest routes REST requests to appropriate gRPC calls
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /v1/projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")

	// Set JSON content type
	w.Header().Set("Content-Type", "application/json")

	// Route based on path structure
	if len(parts) >= 4 && parts[0] == "projects" && parts[2] == "locations" {
		parent := fmt.Sprintf("projects/%s/locations/%s", parts[1], parts[3])

		// KeyRings operations
		if len(parts) == 5 && parts[4] == "keyRings" {
			switch r.Method {
			case http.MethodGet:
				s.listKeyRings(ctx, w, r, parent)
			case http.MethodPost:
				s.createKeyRing(ctx, w, r, parent)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}

		// CryptoKeys operations under a keyring
		if len(parts) == 7 && parts[4] == "keyRings" && parts[6] == "cryptoKeys" {
			keyRingName := fmt.Sprintf("%s/keyRings/%s", parent, parts[5])
			switch r.Method {
			case http.MethodGet:
				s.listCryptoKeys(ctx, w, r, keyRingName)
			case http.MethodPost:
				s.createCryptoKey(ctx, w, r, keyRingName)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}

		// Individual KeyRing operations
		if len(parts) == 6 && parts[4] == "keyRings" {
			keyRingName := fmt.Sprintf("%s/keyRings/%s", parent, parts[5])

			// GetKeyRing
			switch r.Method {
			case http.MethodGet:
				s.getKeyRing(ctx, w, r, keyRingName)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}

		// CryptoKey operations
		if len(parts) == 8 && parts[4] == "keyRings" && parts[6] == "cryptoKeys" {
			cryptoKeyName := fmt.Sprintf("%s/keyRings/%s/cryptoKeys/%s", parent, parts[5], parts[7])

			// Check for :encrypt or :decrypt suffix
			if strings.HasSuffix(parts[7], ":encrypt") {
				cryptoKeyName = strings.TrimSuffix(cryptoKeyName, ":encrypt")
				s.encrypt(ctx, w, r, cryptoKeyName)
				return
			}
			if strings.HasSuffix(parts[7], ":decrypt") {
				cryptoKeyName = strings.TrimSuffix(cryptoKeyName, ":decrypt")
				s.decrypt(ctx, w, r, cryptoKeyName)
				return
			}
			if strings.HasSuffix(parts[7], ":updatePrimaryVersion") {
				cryptoKeyName = strings.TrimSuffix(cryptoKeyName, ":updatePrimaryVersion")
				s.updateCryptoKeyPrimaryVersion(ctx, w, r, cryptoKeyName)
				return
			}

			// GetCryptoKey
			switch r.Method {
			case http.MethodGet:
				s.getCryptoKey(ctx, w, r, cryptoKeyName)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}

		// CryptoKeyVersions list operations
		if len(parts) == 9 && parts[4] == "keyRings" && parts[6] == "cryptoKeys" && parts[8] == "cryptoKeyVersions" {
			cryptoKeyName := fmt.Sprintf("%s/keyRings/%s/cryptoKeys/%s", parent, parts[5], parts[7])
			switch r.Method {
			case http.MethodGet:
				s.listCryptoKeyVersions(ctx, w, r, cryptoKeyName)
			case http.MethodPost:
				s.createCryptoKeyVersion(ctx, w, r, cryptoKeyName)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}

		// Individual CryptoKeyVersion operations
		if len(parts) == 10 && parts[4] == "keyRings" && parts[6] == "cryptoKeys" && parts[8] == "cryptoKeyVersions" {
			versionName := fmt.Sprintf("%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", parent, parts[5], parts[7], parts[9])

			if strings.HasSuffix(parts[9], ":destroy") {
				versionName = strings.TrimSuffix(versionName, ":destroy")
				s.destroyCryptoKeyVersion(ctx, w, r, versionName)
				return
			}

			switch r.Method {
			case http.MethodGet:
				s.getCryptoKeyVersion(ctx, w, r, versionName)
			case http.MethodPatch:
				s.updateCryptoKeyVersion(ctx, w, r, versionName)
			default:
				http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			}
			return
		}
	}

	http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
}

// Helper to write protobuf response as JSON
func writeProtoJSON(w http.ResponseWriter, msg interface{}) {
	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
	}

	protoMsg, ok := msg.(interface{ ProtoReflect() protoreflect.Message })
	if !ok {
		http.Error(w, `{"error":"Failed to marshal response: not a proto message"}`, http.StatusInternalServerError)
		return
	}

	data, err := marshaler.Marshal(protoMsg)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to marshal response: %v"}`, err), http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(data); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to write response: %v"}`, err), http.StatusInternalServerError)
	}
}

// KeyRing operations
func (s *Server) createKeyRing(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	keyRingID := r.URL.Query().Get("keyRingId")
	if keyRingID == "" {
		http.Error(w, `{"error":"keyRingId query parameter required"}`, http.StatusBadRequest)
		return
	}

	req := &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: keyRingID,
	}

	resp, err := s.grpcClient.CreateKeyRing(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeProtoJSON(w, resp)
}

func (s *Server) getKeyRing(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	req := &kmspb.GetKeyRingRequest{Name: name}

	resp, err := s.grpcClient.GetKeyRing(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusNotFound)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) listKeyRings(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	req := &kmspb.ListKeyRingsRequest{
		Parent:    parent,
		PageSize:  100,
		PageToken: r.URL.Query().Get("pageToken"),
	}

	resp, err := s.grpcClient.ListKeyRings(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

// CryptoKey operations
func (s *Server) createCryptoKey(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var cryptoKey kmspb.CryptoKey
	if err := protojson.Unmarshal(body, &cryptoKey); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	cryptoKeyID := r.URL.Query().Get("cryptoKeyId")
	if cryptoKeyID == "" {
		http.Error(w, `{"error":"cryptoKeyId query parameter required"}`, http.StatusBadRequest)
		return
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      parent,
		CryptoKeyId: cryptoKeyID,
		CryptoKey:   &cryptoKey,
	}

	resp, err := s.grpcClient.CreateCryptoKey(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeProtoJSON(w, resp)
}

func (s *Server) getCryptoKey(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	req := &kmspb.GetCryptoKeyRequest{Name: name}

	resp, err := s.grpcClient.GetCryptoKey(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusNotFound)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) listCryptoKeys(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	req := &kmspb.ListCryptoKeysRequest{
		Parent:    parent,
		PageSize:  100,
		PageToken: r.URL.Query().Get("pageToken"),
	}

	resp, err := s.grpcClient.ListCryptoKeys(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) createCryptoKeyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	req := &kmspb.CreateCryptoKeyVersionRequest{
		Parent: parent,
	}

	resp, err := s.grpcClient.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeProtoJSON(w, resp)
}

func (s *Server) updateCryptoKeyPrimaryVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var reqBody struct {
		CryptoKeyVersionID string `json:"cryptoKeyVersionId"`
	}

	if err := json.Unmarshal(body, &reqBody); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	if reqBody.CryptoKeyVersionID == "" {
		http.Error(w, `{"error":"cryptoKeyVersionId is required"}`, http.StatusBadRequest)
		return
	}

	req := &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
		Name:               name,
		CryptoKeyVersionId: reqBody.CryptoKeyVersionID,
	}

	resp, err := s.grpcClient.UpdateCryptoKeyPrimaryVersion(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) listCryptoKeyVersions(ctx context.Context, w http.ResponseWriter, r *http.Request, parent string) {
	req := &kmspb.ListCryptoKeyVersionsRequest{
		Parent:    parent,
		PageSize:  100,
		PageToken: r.URL.Query().Get("pageToken"),
	}

	resp, err := s.grpcClient.ListCryptoKeyVersions(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) getCryptoKeyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	req := &kmspb.GetCryptoKeyVersionRequest{Name: name}

	resp, err := s.grpcClient.GetCryptoKeyVersion(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusNotFound)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) updateCryptoKeyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var version kmspb.CryptoKeyVersion
	if err := protojson.Unmarshal(body, &version); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	version.Name = name

	req := &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &version,
	}

	resp, err := s.grpcClient.UpdateCryptoKeyVersion(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) destroyCryptoKeyVersion(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	req := &kmspb.DestroyCryptoKeyVersionRequest{Name: name}

	resp, err := s.grpcClient.DestroyCryptoKeyVersion(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

// Encryption operations
func (s *Server) encrypt(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var reqBody struct {
		Plaintext string `json:"plaintext"`
	}

	if err := json.Unmarshal(body, &reqBody); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	// Decode base64 plaintext
	plaintext, err := base64.StdEncoding.DecodeString(reqBody.Plaintext)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid base64 plaintext: %v"}`, err), http.StatusBadRequest)
		return
	}

	req := &kmspb.EncryptRequest{
		Name:      name,
		Plaintext: plaintext,
	}

	resp, err := s.grpcClient.Encrypt(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}

func (s *Server) decrypt(ctx context.Context, w http.ResponseWriter, r *http.Request, name string) {
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var reqBody struct {
		Ciphertext string `json:"ciphertext"`
	}

	if err := json.Unmarshal(body, &reqBody); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	// Decode base64 ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(reqBody.Ciphertext)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Invalid base64 ciphertext: %v"}`, err), http.StatusBadRequest)
		return
	}

	req := &kmspb.DecryptRequest{
		Name:       name,
		Ciphertext: ciphertext,
	}

	resp, err := s.grpcClient.Decrypt(ctx, req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	writeProtoJSON(w, resp)
}
