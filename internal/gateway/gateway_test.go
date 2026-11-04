package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGoogleErrorHandler_UsesCloudKMSErrorShape(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantHTTP   int
		wantStatus string
		wantMsg    string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "Decryption failed: the ciphertext is invalid."), 400, "INVALID_ARGUMENT", "Decryption failed: the ciphertext is invalid."},
		{"failed precondition", status.Error(codes.FailedPrecondition, "v is not enabled, current state is: DISABLED."), 400, "FAILED_PRECONDITION", "v is not enabled, current state is: DISABLED."},
		{"not found", status.Error(codes.NotFound, "k not found"), 404, "NOT_FOUND", "k not found"},
		{"malformed body", errors.New("proto: syntax error (line 1:2): unexpected token"), 400, "INVALID_ARGUMENT", "request body is not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/x", nil)
			googleErrorHandler(context.Background(), runtime.NewServeMux(), &runtime.JSONPb{}, rec, req, tc.err)

			if rec.Code != tc.wantHTTP {
				t.Fatalf("HTTP status = %d, want %d", rec.Code, tc.wantHTTP)
			}
			var body struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
					Status  string `json:"status"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v: %s", err, rec.Body.String())
			}
			if body.Error.Code != tc.wantHTTP || body.Error.Status != tc.wantStatus || body.Error.Message != tc.wantMsg {
				t.Errorf("error = %+v, want code %d status %s message %q", body.Error, tc.wantHTTP, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}
