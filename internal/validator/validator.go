package validator

import (
	"errors"
	"reflect"
	"strings"

	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Tell the validator to read the "json" tag for field names
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	// Register custom aliases
	validate.RegisterAlias("app_email", "required,email,max=255")
	validate.RegisterAlias("app_password", "required,min=8,max=72")
}

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
			idx := i
			batchErrs := parseValidationErr(err, &idx)
			allErrors = append(allErrors, batchErrs...)
		}
	}
	return allErrors
}
