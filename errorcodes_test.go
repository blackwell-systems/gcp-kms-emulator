package gcp_kms_emulator_test

import (
	"context"
	"strings"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Errors a caller can cause must carry the status code Cloud KMS returns for
// them, never INTERNAL, so clients can tell a bad request from a server fault.

func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil error", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("expected %s, got %s: %v", want, got, err)
	}
}

func createSymmetricKey(t *testing.T, client kmspb.KeyManagementServiceClient, krName, id string) *kmspb.CryptoKey {
	t.Helper()
	key, err := client.CreateCryptoKey(context.Background(), &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: id,
		CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}
	return key
}

func TestErrorCodes_Encrypt_PrimaryDisabled(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "err-enc-disabled")
	defer cleanup()
	ctx := context.Background()

	key := createSymmetricKey(t, client, krName, "disabled-primary")
	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			Name:  key.Primary.Name,
			State: kmspb.CryptoKeyVersion_DISABLED,
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	if err != nil {
		t.Fatalf("UpdateCryptoKeyVersion: %v", err)
	}

	_, err = client.Encrypt(ctx, &kmspb.EncryptRequest{Name: key.Name, Plaintext: []byte("data")})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestErrorCodes_Decrypt_InvalidCiphertext(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "err-dec-invalid")
	defer cleanup()
	ctx := context.Background()

	key := createSymmetricKey(t, client, krName, "invalid-ciphertext")

	t.Run("garbage", func(t *testing.T) {
		_, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:       key.Name,
			Ciphertext: []byte("this is not a ciphertext produced by this key"),
		})
		requireCode(t, err, codes.InvalidArgument)
	})

	t.Run("too short", func(t *testing.T) {
		_, err := client.Decrypt(ctx, &kmspb.DecryptRequest{Name: key.Name, Ciphertext: []byte{1, 2, 3}})
		requireCode(t, err, codes.InvalidArgument)
	})

	t.Run("wrong AAD", func(t *testing.T) {
		enc, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
			Name:                        key.Name,
			Plaintext:                   []byte("data"),
			AdditionalAuthenticatedData: []byte("right"),
		})
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		_, err = client.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:                        key.Name,
			Ciphertext:                  enc.Ciphertext,
			AdditionalAuthenticatedData: []byte("wrong"),
		})
		requireCode(t, err, codes.InvalidArgument)
	})
}

func TestErrorCodes_ListKeyRings_InvalidPageToken(t *testing.T) {
	client, _, cleanup := conformanceSetup(t, "err-page-token")
	defer cleanup()

	_, err := client.ListKeyRings(context.Background(), &kmspb.ListKeyRingsRequest{
		Parent:    "projects/conformance/locations/global",
		PageToken: "not-a-token",
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestErrorCodes_RawDecrypt_InvalidCiphertext(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "err-raw-dec")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "raw-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}

	enc, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{Name: key.Primary.Name, Plaintext: []byte("data")})
	if err != nil {
		t.Fatalf("RawEncrypt: %v", err)
	}
	tampered := append([]byte(nil), enc.Ciphertext...)
	tampered[0] ^= 0xff

	_, err = client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                 key.Primary.Name,
		Ciphertext:           tampered,
		InitializationVector: enc.InitializationVector,
		TagLength:            enc.TagLength,
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestErrorCodes_GenerateRandomBytes_InvalidLength(t *testing.T) {
	client, _, cleanup := conformanceSetup(t, "err-random")
	defer cleanup()

	for _, n := range []int32{0, -1, 1025} {
		_, err := client.GenerateRandomBytes(context.Background(), &kmspb.GenerateRandomBytesRequest{
			Location:    "projects/conformance/locations/global",
			LengthBytes: n,
		})
		requireCode(t, err, codes.InvalidArgument)
	}
}

// Clients match these messages, so they use Cloud KMS's wording.
func TestErrorCodes_Messages_UseCloudKMSWording(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "err-messages")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "signer",
		CryptoKey: &kmspb.CryptoKey{
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}
	version := key.Name + "/cryptoKeyVersions/1"
	if _, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{Name: version, State: kmspb.CryptoKeyVersion_DISABLED},
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	}); err != nil {
		t.Fatalf("UpdateCryptoKeyVersion: %v", err)
	}
	digest := &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: make([]byte, 32)}}
	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: version, Digest: digest})
	requireCode(t, err, codes.FailedPrecondition)
	if want := version + " is not enabled, current state is: DISABLED"; !strings.Contains(status.Convert(err).Message(), want) {
		t.Errorf("disabled version message = %q, want it to contain %q", status.Convert(err).Message(), want)
	}

	sym := createSymmetricKey(t, client, krName, "sym")
	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{Name: sym.Name + "/cryptoKeyVersions/1", Digest: digest})
	requireCode(t, err, codes.FailedPrecondition)
	if want := sym.Name + " has incorrect key purpose"; !strings.Contains(status.Convert(err).Message(), want) {
		t.Errorf("wrong purpose message = %q, want it to contain %q", status.Convert(err).Message(), want)
	}
}

// Cloud KMS sets verified_success_integrity to the value of success, and
// clients discard a response where the two differ.
func TestMacVerify_SuccessIntegrityMirrorsSuccess(t *testing.T) {
	client, krName, cleanup := conformanceSetup(t, "mac-integrity")
	defer cleanup()
	ctx := context.Background()

	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      krName,
		CryptoKeyId: "mac",
		CryptoKey: &kmspb.CryptoKey{
			Purpose:         kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256},
		},
	})
	if err != nil {
		t.Fatalf("CreateCryptoKey: %v", err)
	}
	version := key.Name + "/cryptoKeyVersions/1"
	signed, err := client.MacSign(ctx, &kmspb.MacSignRequest{Name: version, Data: []byte("msg")})
	if err != nil {
		t.Fatalf("MacSign: %v", err)
	}
	bad := append([]byte(nil), signed.Mac...)
	bad[0] ^= 1

	for _, tc := range []struct {
		name string
		mac  []byte
		want bool
	}{{"valid tag", signed.Mac, true}, {"invalid tag", bad, false}} {
		resp, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{Name: version, Data: []byte("msg"), Mac: tc.mac})
		if err != nil {
			t.Fatalf("%s: MacVerify: %v", tc.name, err)
		}
		if resp.Success != tc.want || resp.VerifiedSuccessIntegrity != tc.want {
			t.Errorf("%s: success=%v verified_success_integrity=%v, want both %v", tc.name, resp.Success, resp.VerifiedSuccessIntegrity, tc.want)
		}
	}
}
