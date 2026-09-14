package portable

import (
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/stretchr/testify/require"
)

func TestPortableTimeECMAScriptBounds(t *testing.T) {
	cases := []struct {
		value time.Time
		text  string
	}{
		{time.UnixMilli(cll.MinPortableUnixMillis).UTC(), "-271821-04-20T00:00:00.000Z"},
		{time.UnixMilli(cll.MaxPortableUnixMillis).UTC(), "+275760-09-13T00:00:00.000Z"},
		{time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), "0001-01-01T00:00:00.000Z"},
	}
	for _, test := range cases {
		formatted, err := FormatTime(test.value)
		require.NoError(t, err)
		require.Equal(t, test.text, formatted)
		parsed, err := ParseTime(test.text)
		require.NoError(t, err)
		require.Equal(t, test.value, parsed)
	}
}

func TestPortableTimeRejectsOutsideBoundsAndNonCanonicalForms(t *testing.T) {
	for _, value := range []time.Time{
		time.UnixMilli(cll.MinPortableUnixMillis).UTC().Add(-time.Millisecond),
		time.UnixMilli(cll.MaxPortableUnixMillis).UTC().Add(time.Millisecond),
		time.Date(1_000_000_000, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		require.Error(t, ValidateTime(value))
		_, err := FormatTime(value)
		require.Error(t, err)
	}

	for _, value := range []string{
		"+000001-01-01T00:00:00.000Z",
		"2026-09-03T12:00:00Z",
		"2026-09-03T12:00:00.000+00:00",
		"2026-02-30T12:00:00.000Z",
	} {
		_, err := ParseTime(value)
		require.Error(t, err)
	}
}
