package gcp_kms_emulator_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	gcp_kms_emulator "github.com/blackwell-systems/gcp-kms-emulator"
	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
)

func ed25519Setup(t *testing.T, ringID string) (kmspb.KeyManagementServiceClient, *kmspb.CryptoKey, func()) {
	t.Helper()
	_, lis, cleanup := setupTestServer(t)
	conn, connCleanup := setupTestClient(t, lis)
	client := kmspb.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	kr, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/test/locations/us-central1",
		KeyRingId: ringID,
	})
	if err != nil {
		t.Fatalf("CreateKeyRing: %v", err)
	}
	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "ed25519-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}
	return client, key, func() { connCleanup(); cleanup() }
}

func parseEd25519PEM(t *testing.T, pemStr string) ed25519.PublicKey {
	t.Helper()
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil || len(rest) != 0 {
		t.Fatalf("expected exactly one PEM block, got %q", pemStr)
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", pub)
	}
	return edPub
}

func TestIntegration_AsymmetricSignVerify_Ed25519(t *testing.T) {
	client, key, cleanup := ed25519Setup(t, "ed25519-sign-ring")
	defer cleanup()
	ctx := context.Background()
	version := key.Primary.Name

	if key.Primary.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		t.Fatalf("algorithm = %v, want EC_SIGN_ED25519", key.Primary.Algorithm)
	}
	if key.Primary.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		t.Fatalf("protection level = %v, want SOFTWARE", key.Primary.ProtectionLevel)
	}

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: version})
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if pubResp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		t.Fatalf("public key algorithm = %v, want EC_SIGN_ED25519", pubResp.Algorithm)
	}
	if pubResp.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		t.Fatalf("public key protection level = %v, want SOFTWARE", pubResp.ProtectionLevel)
	}
	if pubResp.Name != version {
		t.Fatalf("public key name = %q, want %q", pubResp.Name, version)
	}
	if got, want := pubResp.PemCrc32C.GetValue(), int64(crc32.Checksum([]byte(pubResp.Pem), crc32.MakeTable(crc32.Castagnoli))); got != want {
		t.Fatalf("pem_crc32c = %d, want %d", got, want)
	}
	pub := parseEd25519PEM(t, pubResp.Pem)

	data := []byte("pure EdDSA signs the message itself")
	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: version, Data: data})
	if err != nil {
		t.Fatalf("AsymmetricSign: %v", err)
	}
	if !ed25519.Verify(pub, data, signResp.Signature) {
		t.Fatal("signature does not verify over the raw data")
	}
	// Pure EdDSA: a signature over the SHA-256 of the data must not verify.
	sum := sha256.Sum256(data)
	if ed25519.Verify(pub, sum[:], signResp.Signature) {
		t.Fatal("signature unexpectedly verifies over a digest of the data")
	}
	if signResp.Name != version {
		t.Fatalf("response name = %q, want %q", signResp.Name, version)
	}
	if signResp.ProtectionLevel != kmspb.ProtectionLevel_SOFTWARE {
		t.Fatalf("response protection level = %v, want SOFTWARE", signResp.ProtectionLevel)
	}
}

func TestIntegration_AsymmetricSign_Ed25519_Rejections(t *testing.T) {
	client, key, cleanup := ed25519Setup(t, "ed25519-reject-ring")
	defer cleanup()
	ctx := context.Background()
	version := key.Primary.Name

	sum := sha256.Sum256([]byte("x"))
	tests := []struct {
		name string
		req  *kmspb.AsymmetricSignRequest
	}{
		{"digest sha256", &kmspb.AsymmetricSignRequest{Name: version, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: sum[:]}}}},
		{"digest sha512", &kmspb.AsymmetricSignRequest{Name: version, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha512{Sha512: make([]byte, 64)}}}},
		{"neither data nor digest", &kmspb.AsymmetricSignRequest{Name: version}},
		{"empty data", &kmspb.AsymmetricSignRequest{Name: version, Data: []byte{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.AsymmetricSign(ctx, tt.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (err %v), want InvalidArgument", status.Code(err), err)
			}
		})
	}
}

func TestIntegration_AsymmetricSign_Ed25519_CRC32C(t *testing.T) {
	client, key, cleanup := ed25519Setup(t, "ed25519-crc-ring")
	defer cleanup()
	ctx := context.Background()
	version := key.Primary.Name
	data := []byte("checksummed data")
	crc := int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))

	resp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: version, Data: data, DataCrc32C: wrapperspb.Int64(crc),
	})
	if err != nil {
		t.Fatalf("AsymmetricSign: %v", err)
	}
	if !resp.VerifiedDataCrc32C {
		t.Error("verified_data_crc32c = false, want true")
	}
	if resp.VerifiedDigestCrc32C {
		t.Error("verified_digest_crc32c = true, want false")
	}
	if want := int64(crc32.Checksum(resp.Signature, crc32.MakeTable(crc32.Castagnoli))); resp.SignatureCrc32C.GetValue() != want {
		t.Errorf("signature_crc32c = %d, want %d", resp.SignatureCrc32C.GetValue(), want)
	}

	// Without a request checksum the verified flag stays false.
	resp, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: version, Data: data})
	if err != nil {
		t.Fatalf("AsymmetricSign (no crc): %v", err)
	}
	if resp.VerifiedDataCrc32C {
		t.Error("verified_data_crc32c = true without a request checksum")
	}

	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: version, Data: data, DataCrc32C: wrapperspb.Int64(crc + 1),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad checksum: code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestIntegration_Ed25519_VersionLifecycle(t *testing.T) {
	client, key, cleanup := ed25519Setup(t, "ed25519-life-ring")
	defer cleanup()
	ctx := context.Background()

	v2, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent:           key.Name,
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKeyVersion: %v", err)
	}
	if v2.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		t.Fatalf("new version algorithm = %v, want EC_SIGN_ED25519", v2.Algorithm)
	}

	// Each version has its own key pair, and signs under its own key.
	pub1, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: key.Primary.Name})
	if err != nil {
		t.Fatalf("GetPublicKey v1: %v", err)
	}
	pub2, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: v2.Name})
	if err != nil {
		t.Fatalf("GetPublicKey v2: %v", err)
	}
	if pub1.Pem == pub2.Pem {
		t.Fatal("two versions share the same public key")
	}
	data := []byte("v2 data")
	sig, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: v2.Name, Data: data})
	if err != nil {
		t.Fatalf("AsymmetricSign v2: %v", err)
	}
	if !ed25519.Verify(parseEd25519PEM(t, pub2.Pem), data, sig.Signature) {
		t.Fatal("v2 signature does not verify under v2 public key")
	}

	// Disabled versions cannot sign but still serve their public key.
	if _, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{Name: v2.Name, State: kmspb.CryptoKeyVersion_DISABLED},
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	}); err != nil {
		t.Fatalf("disable v2: %v", err)
	}
	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: v2.Name, Data: data})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sign with disabled version: code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: v2.Name}); err != nil {
		t.Fatalf("GetPublicKey on disabled version: %v", err)
	}

	// Destroy schedules destruction; the version can no longer sign.
	if _, err := client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{Name: v2.Name}); err != nil {
		t.Fatalf("DestroyCryptoKeyVersion: %v", err)
	}
	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: v2.Name, Data: data})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sign with destroyed version: code = %v, want FailedPrecondition", status.Code(err))
	}
}

// TestREST_AsymmetricSign_Ed25519 drives the same flow through the REST gateway.
func TestREST_AsymmetricSign_Ed25519(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	kmsServer, err := server.NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	kmspb.RegisterKeyManagementServiceServer(grpcServer, kmsServer)
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	handler, err := gcp_kms_emulator.NewGatewayHandler(lis.Addr().String())
	if err != nil {
		t.Fatalf("NewGatewayHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		out := map[string]any{}
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("decode %s %s: %v (%s)", method, path, err, buf.String())
		}
		return resp.StatusCode, out
	}

	const ring = "/v1/projects/rest/locations/global/keyRings/ed-ring"
	if code, out := do("POST", "/v1/projects/rest/locations/global/keyRings?keyRingId=ed-ring", `{}`); code != 200 {
		t.Fatalf("CreateKeyRing: %d %v", code, out)
	}
	code, out := do("POST", ring+"/cryptoKeys?cryptoKeyId=ed-key",
		`{"purpose":"ASYMMETRIC_SIGN","versionTemplate":{"algorithm":"EC_SIGN_ED25519","protectionLevel":"SOFTWARE"}}`)
	if code != 200 {
		t.Fatalf("CreateCryptoKey: %d %v", code, out)
	}
	version := ring + "/cryptoKeys/ed-key/cryptoKeyVersions/1"

	code, out = do("GET", version+"/publicKey", "")
	if code != 200 {
		t.Fatalf("GetPublicKey: %d %v", code, out)
	}
	if out["algorithm"] != "EC_SIGN_ED25519" || out["protectionLevel"] != "SOFTWARE" {
		t.Fatalf("publicKey algorithm/protectionLevel = %v/%v", out["algorithm"], out["protectionLevel"])
	}
	pub := parseEd25519PEM(t, out["pem"].(string))

	data := []byte("rest message")
	code, out = do("POST", version+":asymmetricSign", `{"data":"`+base64.StdEncoding.EncodeToString(data)+`"}`)
	if code != 200 {
		t.Fatalf("asymmetricSign: %d %v", code, out)
	}
	sig, err := base64.StdEncoding.DecodeString(out["signature"].(string))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("REST signature does not verify")
	}
	if want := strings.TrimPrefix(version, "/v1/"); out["name"] != want {
		t.Fatalf("name = %v, want %v", out["name"], want)
	}

	sum := sha256.Sum256(data)
	code, out = do("POST", version+":asymmetricSign", `{"digest":{"sha256":"`+base64.StdEncoding.EncodeToString(sum[:])+`"}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("digest sign: status %d %v, want 400", code, out)
	}
	code, out = do("POST", version+":asymmetricSign", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty sign: status %d %v, want 400", code, out)
	}
}
