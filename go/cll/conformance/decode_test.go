package conformance

import (
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/stretchr/testify/require"
)

// Times outside the portable range must reach the backend under test, so a
// backend that accepts them fails the time-range case.
func TestDecodeTimeLeavesRangeToTheBackend(t *testing.T) {
	late, err := decodeTime("+275760-09-13T00:00:00.001Z")
	require.NoError(t, err)
	require.Equal(t, cll.MaxPortableUnixMillis+1, late.UnixMilli())
	early, err := decodeTime("-271821-04-19T23:59:59.999Z")
	require.NoError(t, err)
	require.Equal(t, cll.MinPortableUnixMillis-1, early.UnixMilli())
	_, err = decodeTime("2026-09-01T12:00:00Z")
	require.ErrorIs(t, err, cll.ErrInvalid)
}
