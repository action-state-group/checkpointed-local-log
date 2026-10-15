package conformance_test

import (
	"context"
	"os"
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/cll/conformance"
	"github.com/action-state-group/checkpointed-local-log/go/store/memory"
	"github.com/stretchr/testify/require"
)

func TestPinnedVectorsMatchRepository(t *testing.T) {
	pinned, err := os.ReadFile("vectors.json")
	require.NoError(t, err)
	shared, err := os.ReadFile("../../../backend-conformance-vectors/vectors.json")
	require.NoError(t, err)
	require.Equal(t, string(shared), string(pinned), "run backend-conformance-vectors/generate.py")
}

// entryOnly hides every method except the entry log, as a user-supplied
// store that implements only cll.EntryStore would.
type entryOnly struct{ store *memory.Store }

func (e entryOnly) ScanEntries(ctx context.Context, after uint64, limit int) ([]cll.Entry, error) {
	return e.store.ScanEntries(ctx, after, limit)
}
func (e entryOnly) Append(ctx context.Context, input cll.AppendInput) (cll.AppendResult, error) {
	return e.store.Append(ctx, input)
}
func (e entryOnly) GetEntry(ctx context.Context, value []byte) (cll.Entry, error) {
	return e.store.GetEntry(ctx, value)
}

func TestEntryStoreSubset(t *testing.T) {
	conformance.Run(t, conformance.Config{Open: func(*testing.T) any { return entryOnly{memory.New()} }})
}
