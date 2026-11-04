package storage

import (
	"fmt"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// ErrNotFound indicates a resource was not found.
type ErrNotFound struct {
	Resource string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("%s not found", e.Resource)
}

// ErrAlreadyExists indicates a resource already exists.
type ErrAlreadyExists struct {
	Resource string
}

func (e *ErrAlreadyExists) Error() string {
	return fmt.Sprintf("%s already exists", e.Resource)
}

// ErrFailedPrecondition indicates an invalid state transition.
type ErrFailedPrecondition struct {
	Message string
}

func (e *ErrFailedPrecondition) Error() string {
	return e.Message
}

// ErrInvalidArgument indicates a request argument is not valid for the target
// resource (for example a digest supplied for a pure-EdDSA key).
type ErrInvalidArgument struct {
	Message string
}

func (e *ErrInvalidArgument) Error() string {
	return e.Message
}

// versionNotEnabled reports an operation on a version that is not ENABLED, in
// the wording Cloud KMS uses, which clients match on.
func versionNotEnabled(name string, state kmspb.CryptoKeyVersion_CryptoKeyVersionState) error {
	return &ErrFailedPrecondition{Message: fmt.Sprintf("%s is not enabled, current state is: %s.", name, state)}
}

// incorrectPurpose reports an operation the key's purpose does not allow, in
// the wording Cloud KMS uses, which clients match on.
func incorrectPurpose(key *StoredCryptoKey, required string) error {
	return &ErrFailedPrecondition{Message: fmt.Sprintf("%s has incorrect key purpose %s; this operation requires %s.", key.Name, key.Purpose, required)}
}
