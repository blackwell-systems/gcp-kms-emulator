// Quick test client for KMS emulator
package main

import (
	"context"
	"fmt"
	"log"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx := context.Background()

	// Connect to emulator
	conn, err := grpc.NewClient(
		"localhost:9090",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	client, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Test workflow
	parent := "projects/test-project/locations/global"

	// 1. Create keyring
	fmt.Println("Creating keyring...")
	keyring, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: "test-keyring",
	})
	if err != nil {
		log.Fatalf("CreateKeyRing failed: %v", err)
	}
	fmt.Printf("✓ Keyring created: %s\n", keyring.Name)

	// 2. Create crypto key
	fmt.Println("Creating crypto key...")
	key, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyring.Name,
		CryptoKeyId: "test-key",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		log.Fatalf("CreateCryptoKey failed: %v", err)
	}
	fmt.Printf("✓ Crypto key created: %s\n", key.Name)

	// 3. Encrypt data
	plaintext := []byte("Hello, KMS Emulator!")
	fmt.Printf("Encrypting: %s\n", plaintext)
	encryptResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      key.Name,
		Plaintext: plaintext,
	})
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("✓ Encrypted (%d bytes)\n", len(encryptResp.Ciphertext))

	// 4. Decrypt data
	fmt.Println("Decrypting...")
	decryptResp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       key.Name,
		Ciphertext: encryptResp.Ciphertext,
	})
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Printf("✓ Decrypted: %s\n", decryptResp.Plaintext)

	// Verify
	if string(decryptResp.Plaintext) == string(plaintext) {
		fmt.Println("\n✓ SUCCESS: Encryption/decryption cycle works!")
	} else {
		fmt.Println("\n✗ FAILED: Plaintext mismatch")
	}
}
