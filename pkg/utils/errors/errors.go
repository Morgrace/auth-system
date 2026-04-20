package errors

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound     = errors.New("resource not found")
	ErrConflict     = errors.New("resource already exists")
	ErrInvalidInput = errors.New("invalid input data")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// --- Error codes ---
const (
	CodeUnauthorized      = "UNAUTHORIZED"
	CodeConflict          = "CONFLICT"
	CodeInvalidInput      = "INVALID_INPUT"
	CodeNotFound          = "NOT_FOUND"
	CodeForbidden         = "FORBIDDEN"
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeInvalidToken      = "INVALID_TOKEN"
	CodeExpiredToken      = "EXPIRED_TOKEN"
	CodeInternalServer    = "INTERNAL_SERVER_ERROR"
)

type DetailedError struct {
	Code    string
	Message string
	Err     error
}

func (e *DetailedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s - %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *DetailedError) Unwrap() error {
	return e.Err
}

// --- Constructors (each sets a sensible default HTTP status) ---
func NewUnauthorized(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeUnauthorized,
		Message: msg,
		Err:     ErrUnauthorized,
	}
}

func NewConflict(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeConflict,
		Message: msg,
		Err:     ErrConflict,
	}
}

func NewInvalidInput(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeInvalidInput,
		Message: msg,
		Err:     ErrInvalidInput,
	}
}

func NewNotFound(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeNotFound,
		Message: msg,
		Err:     ErrNotFound,
	}
}

func NewForbidden(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeForbidden,
		Message: msg,
		Err:     ErrForbidden,
	}
}
func NewInvalidCredentials(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeInvalidCredentials,
		Message: msg,
		Err:     ErrUnauthorized,
	}
}

func NewInvalidToken(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeInvalidToken,
		Message: msg,
		Err:     ErrUnauthorized,
	}
}
func NewExpiredToken(msg string) *DetailedError {
	return &DetailedError{
		Code:    CodeExpiredToken,
		Message: msg,
		Err:     ErrUnauthorized,
	}
}

func NewInternalServerError(msg string, err error) *DetailedError {
	return &DetailedError{
		Code:    CodeInternalServer,
		Message: msg,
		Err:     err,
	}
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Index   *int   `json:"index,omitempty"`
}

type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	return "validation failed"
}
