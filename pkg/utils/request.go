package utils

import (
	"encoding/json"
	"net/http"

	"github.com/Morgrace/auth-system/internal/validator"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
)

func DecodeAndValidate(w http.ResponseWriter, r *http.Request, req any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		HandleError(w, r, appErrors.ErrInvalidInput)
		return false
	}
	if err := validator.ValidateOne(req); err != nil {
		HandleError(w, r, err)
		return false
	}
	return true
}
