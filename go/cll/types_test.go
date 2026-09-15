package cll

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntryCloneDoesNotAliasValue(t *testing.T) {
	original := Entry{Value: []byte("entry")}
	cloned := original.Clone()

	cloned.Value[0] = 'E'
	require.Equal(t, []byte("entry"), original.Value)
	require.Equal(t, []byte("Entry"), cloned.Value)
}
