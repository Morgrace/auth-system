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
	Status  ResponseStatus `json:"status"`
	Data    interface{}    `json:"data,omitempty"`
	Message string         `json:"message,omitempty"`
	Error   *ErrorPayload  `json:"error,omitempty"`
	Meta    Meta           `json:"meta"`
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

func WriteSuccess(w http.ResponseWriter, r *http.Request, statusCode int, data interface{}, message ...string) {
	msg := ""
	if len(message) > 0 {
		msg = message[0]
	}
	payload := APIResponse{
		Status:  StatusSuccess,
		Message: msg,
		Data:    data,
		Meta:    generateMeta(r),
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

// sentinelToStatus maps sentinel errors to HTTP status codes.
func sentinelToStatus(err error) int {
	switch {
	case errors.Is(err, appErrors.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, appErrors.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, appErrors.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, appErrors.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, appErrors.ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
func sentinelToCodeAndMessage(statusCode int) (code, message string) {
	switch statusCode {
	case http.StatusNotFound:
		return appErrors.CodeNotFound, "Resource not found"
	case http.StatusConflict:
		return appErrors.CodeConflict, "Resource already exists"
	case http.StatusBadRequest:
		return appErrors.CodeInvalidInput, "Invalid input"
	case http.StatusUnauthorized:
		return appErrors.CodeUnauthorized, "Unauthorized"
	case http.StatusForbidden:
		return appErrors.CodeForbidden, "Forbidden"
	default:
		return appErrors.CodeInternalServer, "Internal server error"
	}
}

// HandleError inspects the error and writes the appropriate HTTP response.
// If userMessage is provided, it overrides the default message.
func HandleError(w http.ResponseWriter, r *http.Request, err error, userMessage ...string) {
	var statusCode int
	var errCode string
	var message string
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
		WriteFail(w, r, statusCode, errCode, "Validation failed", details)
		return
	}

	// 2. DetailedError
	var detailedErr *appErrors.DetailedError
	if errors.As(err, &detailedErr) {
		statusCode = sentinelToStatus(detailedErr.Err)
		if len(userMessage) > 0 && userMessage[0] != "" {
			message = userMessage[0]
		} else {
			message = detailedErr.Message
		}

		if statusCode >= 500 {
			log.Printf("Internal server error: %v", err)
			WriteServerError(w, r, detailedErr.Code, message)
			return
		}
		WriteFail(w, r, statusCode, detailedErr.Code, message, nil)
		return
	}

	// Fallback
	statusCode = sentinelToStatus(err)
	errCode, message = sentinelToCodeAndMessage(statusCode)

	if len(userMessage) > 0 && userMessage[0] != "" {
		message = userMessage[0]
	}

	if statusCode >= 500 {
		log.Printf("Internal server error: %v", err)
		WriteServerError(w, r, errCode, message)
		return
	}
	WriteFail(w, r, statusCode, errCode, message, nil)

}
