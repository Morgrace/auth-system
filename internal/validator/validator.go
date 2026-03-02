package validator

import (
	"errors"

	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func ValidateOne(s any) appErrors.ValidationErrors {
	err := validate.Struct(s)
	if err != nil {
		return parseValidationErr(err, nil)
	}
	return nil
}

func parseValidationErr(err error, index *int) appErrors.ValidationErrors {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		out := make(appErrors.ValidationErrors, len(validationErrors))
		for i, fieldErr := range validationErrors {
			out[i] = appErrors.ValidationError{
				Field:   fieldErr.Field(),
				Message: msgForTag(fieldErr.Tag()),
				Code:    fieldErr.Tag(),
				Index:   index,
			}
		}
		return out
	}
	return nil
}

func msgForTag(tag string) string {
	switch tag {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	// ... others
	default:
		return "Invalid value"
	}
}

// ValidateBatch validates each element in a slice.
// It returns all validation errors across all elements, with the index set.
func ValidateBatch[T any](items []T) appErrors.ValidationErrors {
	var allErrors appErrors.ValidationErrors

	for i, item := range items {
		err := validate.Struct(item)
		if err != nil {
			// pass the current index so errors from this item include it
			batchErrs := parseValidationErr(err, &i)
			allErrors = append(allErrors, batchErrs...)
		}
	}
	return allErrors
}
