package server

import (
	"hash/crc32"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32cValue(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}
