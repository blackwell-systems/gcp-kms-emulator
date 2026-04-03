package storage

import "fmt"

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
