package utils

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
	"github.com/google/uuid"
)

type ResponseStatus string

const (
	StatusSuccess ResponseStatus = "success"
	StatusError   ResponseStatus = "error"
	StatusFail    ResponseStatus = "fail"
)

type Meta struct {
	Timestamp string `json:"timestamp"`
	RequestID string `json:"requestId"`
	Path      string `json:"path,omitempty"`
	Method    string `json:"method,omitempty"`
}

type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Index   *int   `json:"index,omitempty"` // now included!
}

type ErrorPayload struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []ErrorDetail `json:"details,omitempty"`
}

type APIResponse struct {
	Status ResponseStatus `json:"status"`
	Data   interface{}    `json:"data,omitempty"`
	Error  *ErrorPayload  `json:"error,omitempty"`
	Meta   Meta           `json:"meta"`
}

func generateMeta(r *http.Request) Meta {
	return Meta{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID: uuid.New().String(),
		Path:      r.URL.Path,
		Method:    r.Method,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func WriteSuccess(w http.ResponseWriter, r *http.Request, statusCode int, data interface{}) {
	payload := APIResponse{
		Status: StatusSuccess,
		Data:   data,
		Meta:   generateMeta(r),
	}
	writeJSON(w, statusCode, payload)
}

func WriteFail(w http.ResponseWriter, r *http.Request, statusCode int, code, message string, details []ErrorDetail) {
	payload := APIResponse{
		Status: StatusFail,
		Error: &ErrorPayload{
			Code:    code,
			Message: message,
			Details: details,
		},
		Meta: generateMeta(r),
	}
	writeJSON(w, statusCode, payload)
}

func WriteServerError(w http.ResponseWriter, r *http.Request, code, message string) {
	payload := APIResponse{
		Status: StatusError,
		Error: &ErrorPayload{
			Code:    code,
			Message: message,
		},
		Meta: generateMeta(r),
	}
	writeJSON(w, http.StatusInternalServerError, payload)
}

// HandleError inspects the error and writes the appropriate HTTP response.
// If userMessage is provided, it overrides the default message.
func HandleError(w http.ResponseWriter, r *http.Request, err error, userMessage ...string) {
	var statusCode int
	var errCode string
	var details []ErrorDetail

	// 1. Check for structured validation errors first
	var valErrs appErrors.ValidationErrors
	if errors.As(err, &valErrs) {
		statusCode = http.StatusBadRequest
		errCode = "VALIDATION_ERROR"
		details = make([]ErrorDetail, len(valErrs))
		for i, ve := range valErrs {
			details[i] = ErrorDetail{
				Field:   ve.Field,
				Message: ve.Message,
				Code:    ve.Code,
				Index:   ve.Index, // preserve index
			}
		}
	} else {
		// 2. Check sentinel errors
		switch {
		case errors.Is(err, appErrors.ErrNotFound):
			statusCode = http.StatusNotFound
			errCode = "NOT_FOUND"
		case errors.Is(err, appErrors.ErrConflict):
			statusCode = http.StatusConflict
			errCode = "CONFLICT"
		case errors.Is(err, appErrors.ErrInvalidInput):
			statusCode = http.StatusBadRequest
			errCode = "INVALID_INPUT"
		case errors.Is(err, appErrors.ErrUnauthorized):
			statusCode = http.StatusUnauthorized
			errCode = "UNAUTHORIZED"
		case errors.Is(err, appErrors.ErrForbidden):
			statusCode = http.StatusForbidden
			errCode = "FORBIDDEN"
		default:
			statusCode = http.StatusInternalServerError
			errCode = "INTERNAL_SERVER_ERROR"
		}
	}

	// Determine the user-facing message
	var message string
	if len(userMessage) > 0 && userMessage[0] != "" {
		message = userMessage[0]
	} else {
		// Default messages
		switch statusCode {
		case http.StatusNotFound:
			message = "Resource not found"
		case http.StatusConflict:
			message = "Resource already exists"
		case http.StatusBadRequest:
			if details != nil {
				message = "Validation failed"
			} else {
				message = "Invalid input"
			}
		case http.StatusUnauthorized:
			message = "Unauthorized"
		case http.StatusForbidden:
			message = "Forbidden"
		default:
			message = "Internal server error"
		}
	}

	// Log internal errors for debugging
	if statusCode >= 500 {
		log.Printf("Internal server error: %v", err)
	}

	// Write the appropriate response
	if statusCode >= 500 {
		WriteServerError(w, r, errCode, message)
	} else {
		WriteFail(w, r, statusCode, errCode, message, details)
	}
}
