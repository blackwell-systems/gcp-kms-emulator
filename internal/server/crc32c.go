package server

import (
	"hash/crc32"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32cValue(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}

// verifyCRC32C verifies a CRC32C checksum against data if provided.
// Returns status.Error(codes.InvalidArgument, "request corrupted in transit")
// on mismatch. Returns nil if provided is nil (no check requested).
func verifyCRC32C(data []byte, provided *wrapperspb.Int64Value) error {
	if provided == nil {
		return nil
	}
	computed := int64(crc32.Checksum(data, crc32cTable))
	if computed != provided.Value {
		return status.Error(codes.InvalidArgument, "request corrupted in transit")
	}
	return nil
}
