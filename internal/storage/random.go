package storage

import (
	"crypto/rand"
	"fmt"
	"io"
)

// GenerateRandomBytes generates cryptographically random bytes of the specified length.
// Length must be between 1 and 1024 inclusive.
func (s *Storage) GenerateRandomBytes(length int32) ([]byte, error) {
	if length <= 0 || length > 1024 {
		return nil, fmt.Errorf("length must be between 1 and 1024, got %d", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return buf, nil
}
