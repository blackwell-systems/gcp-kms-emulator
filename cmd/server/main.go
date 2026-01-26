// GCP KMS Emulator Server
//
// A lightweight emulator implementation of Google Cloud KMS API for local testing.
// This server implements the gRPC KMS API without requiring GCP credentials.
//
// Usage:
//
//	gcp-kms-emulator --port 9090
//
// Environment Variables:
//
//	GCP_KMS_PORT        - Port to listen on (default: 9090)
//	GCP_KMS_LOG_LEVEL   - Log level: debug, info, warn, error (default: info)
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/blackwell-systems/gcp-kms-emulator/internal/server"
)

var (
	port     = flag.Int("port", getEnvInt("GCP_KMS_PORT", 9090), "Port to listen on")
	logLevel = flag.String("log-level", getEnv("GCP_KMS_LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	version  = "0.1.0"
)

func main() {
	flag.Parse()

	log.Printf("GCP KMS Emulator v%s", version)
	log.Printf("Starting on port %d with log level: %s", *port, *logLevel)

	// Create listener
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create and register KMS service
	kmsServer := server.NewServer()
	kmspb.RegisterKeyManagementServiceServer(grpcServer, kmsServer)

	// Register reflection service (for grpc_cli debugging)
	reflection.Register(grpcServer)

	log.Printf("Server listening at %v", lis.Addr())
	log.Printf("Ready to accept connections")

	// Start server in goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	grpcServer.GracefulStop()
	log.Println("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}
