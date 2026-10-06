package cll

import (
	"fmt"
	"regexp"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)

// ValidateIdentifier enforces the cross-runtime identifier subset.
func ValidateIdentifier(value string) error {
	length := len([]byte(value))
	if length < 1 || length > MaxIdentifierBytes || !identifierPattern.MatchString(value) {
		return fmt.Errorf("%w: identifier must be 1..%d UTF-8 bytes in portable subset", ErrInvalid, MaxIdentifierBytes)
	}
	return nil
}
