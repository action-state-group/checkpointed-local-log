package checkpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/store/memory"
	"github.com/stretchr/testify/require"
)

type countingCheckpointStore struct {
	cll.CheckpointStore
	loads       int
	contendOnce bool
}

func (s *countingCheckpointStore) LoadCLL(ctx context.Context) (cll.State, error) {
	s.loads++
	return s.CheckpointStore.LoadCLL(ctx)
}

func (s *countingCheckpointStore) CommitCLL(ctx context.Context, expectedSize uint64, expectedCheckpoint []byte, next cll.State) error {
	if s.contendOnce {
		s.contendOnce = false
		return cll.ErrContention
	}
	return s.CheckpointStore.CommitCLL(ctx, expectedSize, expectedCheckpoint, next)
}

func TestCatchUpReusesVerifiedTreeAcrossBatches(t *testing.T) {
	base, signer, started := catchUpFixture(t, 3)
	store := &countingCheckpointStore{CheckpointStore: base}
	config := DefaultRunnerConfig("generic-log")
	config.ScanLimit = 1
	runner, err := NewRunner(config, store, signer)
	require.NoError(t, err)

	require.NoError(t, runner.catchUp(t.Context(), started))
	require.Equal(t, 1, store.loads)
	state, err := base.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(3), state.IndexedSeq)
}

func TestCatchUpDiscardsCachedTreeAfterContention(t *testing.T) {
	base, signer, started := catchUpFixture(t, 2)
	store := &countingCheckpointStore{CheckpointStore: base, contendOnce: true}
	config := DefaultRunnerConfig("generic-log")
	config.ScanLimit = 1
	runner, err := NewRunner(config, store, signer)
	require.NoError(t, err)

	require.NoError(t, runner.catchUp(t.Context(), started))
	require.Equal(t, 2, store.loads)
	state, err := base.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(2), state.IndexedSeq)
}

func catchUpFixture(t *testing.T, count int) (*memory.Store, *Ed25519Signer, time.Time) {
	t.Helper()
	store := memory.New()
	started := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	for index := 1; index <= count; index++ {
		_, err := store.Append(t.Context(), cll.AppendInput{
			Value:      bytes.Repeat([]byte{byte(index)}, cll.EntryBytes),
			AppendedAt: started.Add(time.Duration(index) * time.Millisecond),
		})
		require.NoError(t, err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519Signer(private)
	require.NoError(t, err)
	return store, signer, started.Add(time.Minute)
}
