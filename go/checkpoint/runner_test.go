package checkpoint_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/store/memory"
	"github.com/stretchr/testify/require"
)

func TestRunnerIndexesAndCheckpointsGenericEntries(t *testing.T) {
	store, signer := runnerFixture(t)
	started := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	appendEntries(t, store, started, 2)
	config := checkpoint.DefaultRunnerConfig("generic-log")
	config.Cadence.CadenceEntries = 2
	config.WitnessIDs = []string{"anchor"}
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)

	changed, err := runner.RunOnce(t.Context(), started.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, changed)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint64(2), state.IndexedSeq)
	require.NotNil(t, state.Checkpoint)
	record, err := checkpoint.ParseRecord(state.Checkpoint.Bytes)
	require.NoError(t, err)
	require.Equal(t, "generic-log", record.LogID)
	pending, err := store.PendingWitnesses(t.Context(), started.Add(time.Minute), 1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
}

func TestRunnerPersistsAgeCadenceWithoutNewEntry(t *testing.T) {
	store, signer := runnerFixture(t)
	started := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	appendEntries(t, store, started, 1)
	config := checkpoint.DefaultRunnerConfig("generic-log")
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)
	changed, err := runner.RunOnce(t.Context(), started)
	require.NoError(t, err)
	require.True(t, changed)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Nil(t, state.Checkpoint)
	require.NotNil(t, state.FirstPendingAt)

	changed, err = runner.RunOnce(t.Context(), started.Add(15*time.Minute))
	require.NoError(t, err)
	require.True(t, changed)
	state, err = store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.NotNil(t, state.Checkpoint)
	require.Nil(t, state.FirstPendingAt)
}

func TestRunnerLinksLatestCheckpoint(t *testing.T) {
	store, signer := runnerFixture(t)
	started := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	config := checkpoint.DefaultRunnerConfig("generic-log")
	config.Cadence.CadenceEntries = 1
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)
	appendEntries(t, store, started, 1)
	_, err = runner.RunOnce(t.Context(), started)
	require.NoError(t, err)
	first, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	firstRecord, err := checkpoint.ParseRecord(first.Checkpoint.Bytes)
	require.NoError(t, err)
	appendEntriesFrom(t, store, started.Add(time.Minute), 2, 1)
	_, err = runner.RunOnce(t.Context(), started.Add(time.Minute))
	require.NoError(t, err)
	second, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	secondRecord, err := checkpoint.ParseRecord(second.Checkpoint.Bytes)
	require.NoError(t, err)
	require.Equal(t, first.Checkpoint.Size, secondRecord.PrevSize)
	require.Equal(t, firstRecord.Root, secondRecord.PrevRoot)
}

func TestRunnerRejectsTamperedCheckpoint(t *testing.T) {
	store, signer := runnerFixture(t)
	started := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	appendEntries(t, store, started, 1)
	config := checkpoint.DefaultRunnerConfig("generic-log")
	config.Cadence.CadenceEntries = 1
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)
	_, err = runner.RunOnce(t.Context(), started)
	require.NoError(t, err)
	tampered := tamperedStore{CheckpointStore: store}
	runner, err = checkpoint.NewRunner(config, tampered, signer)
	require.NoError(t, err)
	_, err = runner.RunOnce(t.Context(), started.Add(time.Minute))
	require.ErrorIs(t, err, cll.ErrCorrupt)
}

type tamperedStore struct{ cll.CheckpointStore }

func (s tamperedStore) LoadCLL(ctx context.Context) (cll.State, error) {
	state, err := s.CheckpointStore.LoadCLL(ctx)
	if err == nil && state.Checkpoint != nil {
		state.Checkpoint.Bytes[len(state.Checkpoint.Bytes)-1] ^= 1
	}
	return state, err
}

func runnerFixture(t *testing.T) (*memory.Store, *checkpoint.Ed25519Signer) {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := checkpoint.NewEd25519Signer(private)
	require.NoError(t, err)
	return store, signer
}

func appendEntries(t *testing.T, store cll.Backend, started time.Time, count int) {
	appendEntriesFrom(t, store, started, 1, count)
}

func appendEntriesFrom(t *testing.T, store cll.Backend, started time.Time, start, count int) {
	t.Helper()
	for number := start; number < start+count; number++ {
		_, err := store.Append(t.Context(), cll.AppendInput{Value: bytes.Repeat([]byte{byte(number)}, cll.EntryBytes), AppendedAt: started.Add(time.Duration(number-start) * time.Second)})
		require.NoError(t, err)
	}
}
