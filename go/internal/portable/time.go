// Package portable implements encodings shared with the TypeScript runtime.
package portable

import (
	"fmt"
	"strconv"
	"time"

	"github.com/action-state-group/cll-go/cll"
)

// NormalizeTime converts a time to UTC with ECMAScript millisecond precision.
func NormalizeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}

// ValidateTime checks the inclusive ECMAScript Date range.
func ValidateTime(value time.Time) error {
	value = NormalizeTime(value)
	minimum := time.UnixMilli(cll.MinPortableUnixMillis).UTC()
	maximum := time.UnixMilli(cll.MaxPortableUnixMillis).UTC()
	if value.Before(minimum) || value.After(maximum) {
		return fmt.Errorf("time is outside the portable range")
	}
	return nil
}

// FormatTime reproduces Date.toISOString(), including expanded signed years.
func FormatTime(value time.Time) (string, error) {
	value = NormalizeTime(value)
	if err := ValidateTime(value); err != nil {
		return "", err
	}
	year := value.Year()
	var yearText string
	if year >= 0 && year <= 9999 {
		yearText = fmt.Sprintf("%04d", year)
	} else {
		sign := "+"
		magnitude := year
		if year < 0 {
			sign = "-"
			magnitude = -year
		}
		yearText = fmt.Sprintf("%s%06d", sign, magnitude)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", yearText,
		value.Month(), value.Day(), value.Hour(), value.Minute(), value.Second(), value.Nanosecond()/int(time.Millisecond)), nil
}

// ParseTime accepts only the exact Date.toISOString() representation.
func ParseTime(value string) (time.Time, error) {
	if len(value) < 24 || value[len(value)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("invalid portable time")
	}
	yearWidth := 4
	yearStart := 0
	if value[0] == '+' || value[0] == '-' {
		yearWidth = 6
		yearStart = 1
	}
	separator := yearStart + yearWidth
	if len(value) != separator+20 || value[separator] != '-' || value[separator+3] != '-' || value[separator+6] != 'T' || value[separator+9] != ':' || value[separator+12] != ':' || value[separator+15] != '.' || value[separator+19] != 'Z' {
		return time.Time{}, fmt.Errorf("invalid portable time")
	}
	parse := func(start, end int) (int, error) { return strconv.Atoi(value[start:end]) }
	year, err := parse(yearStart, separator)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable year: %w", err)
	}
	if yearStart == 1 && value[0] == '-' {
		year = -year
	}
	month, err := parse(separator+1, separator+3)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable month: %w", err)
	}
	day, err := parse(separator+4, separator+6)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable day: %w", err)
	}
	hour, err := parse(separator+7, separator+9)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable hour: %w", err)
	}
	minute, err := parse(separator+10, separator+12)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable minute: %w", err)
	}
	second, err := parse(separator+13, separator+15)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable second: %w", err)
	}
	millisecond, err := parse(separator+16, separator+19)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid portable millisecond: %w", err)
	}
	parsed := time.Date(year, time.Month(month), day, hour, minute, second, millisecond*int(time.Millisecond), time.UTC)
	formatted, err := FormatTime(parsed)
	if err != nil || formatted != value {
		return time.Time{}, fmt.Errorf("invalid portable time")
	}
	return parsed, nil
}
