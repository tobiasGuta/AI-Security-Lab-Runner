package validation

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrInvalidName = errors.New("invalid identifier name")

	identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

func ValidateIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("%w: identifier cannot be empty", ErrInvalidName)
	}
	if !identifierRegex.MatchString(name) {
		return fmt.Errorf("%w: '%s' contains invalid characters", ErrInvalidName, name)
	}
	return nil
}
