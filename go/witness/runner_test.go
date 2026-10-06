package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/store/memory"
	"github.com/stretchr/testify/require"
)

func TestDeliveryRunnerJitterSupportsMaximumDuration(t *testing.T) {
	config := DefaultDeliveryConfig()
	config.BaseBackoff = time.Duration(math.MaxInt64)
	config.MaxBackoff = time.Duration(math.MaxInt64)
	runner := &DeliveryRunner{config: config}
	require.NotPanics(t, func() {
		delay := runner.backoff(1)
		require.GreaterOrEqual(t, delay, time.Duration(0))
		require.Less(t, delay, config.MaxBackoff)
	})
}

func TestDeliveryRunnerBackoffReachesNonPowerOfTwoMaximum(t *testing.T) {
	config := DefaultDeliveryConfig()
	config.BaseBackoff = time.Second
	config.MaxBackoff = 2500 * time.Millisecond
	config.Jitter = false
	runner := &DeliveryRunner{config: config}
	require.Equal(t, config.MaxBackoff, runner.backoff(2))
}

type fakeSubmitter struct {
	receipt Receipt
	err     error
}

func (f fakeSubmitter) Submit(context.Context, []byte) (Receipt, error) { return f.receipt, f.err }

type fakeVerifier struct{ err error }

func (f fakeVerifier) Verify([]byte, Receipt) error { return f.err }

type nonTimeoutNetworkError struct{}

func (nonTimeoutNetworkError) Error() string   { return "connection refused" }
func (nonTimeoutNetworkError) Timeout() bool   { return false }
func (nonTimeoutNetworkError) Temporary() bool { return true }

type cancelingSubmitter struct{ cancel context.CancelFunc }

func (s cancelingSubmitter) Submit(ctx context.Context, _ []byte) (Receipt, error) {
	s.cancel()
	return Receipt{}, ctx.Err()
}

func TestNonTimeoutNetworkErrorsAreRetryable(t *testing.T) {
	require.True(t, IsRetryable(nonTimeoutNetworkError{}))
}

func TestDeliveryRunnerDoesNotPersistCallerCancellation(t *testing.T) {
	store, now := pendingStore(t, []string{"anchor"})
	ctx, cancel := context.WithCancel(t.Context())
	runner, err := NewDeliveryRunner(
		DefaultDeliveryConfig(),
		store,
		map[string]Submitter{"anchor": cancelingSubmitter{cancel: cancel}},
		map[string]Verifier{"anchor": fakeVerifier{}},
	)
	require.NoError(t, err)
	_, err = runner.RunOnce(ctx, now, 1)
	require.ErrorIs(t, err, context.Canceled)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.Zero(t, state.Witnesses[0].Attempts)
	require.False(t, state.Witnesses[0].Permanent)
}

func TestDeliveryRunnerPersistsRetryAndPermanentFailure(t *testing.T) {
	store, now := pendingStore(t, []string{"anchor"})
	config := DefaultDeliveryConfig()
	config.Jitter = false
	runner, err := NewDeliveryRunner(config, store,
		map[string]Submitter{"anchor": fakeSubmitter{err: &HTTPError{StatusCode: http.StatusTooManyRequests, Body: "slow"}}},
		map[string]Verifier{"anchor": fakeVerifier{}},
	)
	require.NoError(t, err)
	completed, err := runner.RunOnce(t.Context(), now, 1)
	require.NoError(t, err)
	require.Zero(t, completed)
	pending, err := store.PendingWitnesses(t.Context(), now.Add(time.Second), 1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, uint32(1), pending[0].Attempts)

	runner, err = NewDeliveryRunner(config, store,
		map[string]Submitter{"anchor": fakeSubmitter{err: &HTTPError{StatusCode: http.StatusConflict, Body: "fork"}}},
		map[string]Verifier{"anchor": fakeVerifier{}},
	)
	require.NoError(t, err)
	_, err = runner.RunOnce(t.Context(), now.Add(time.Second), 1)
	require.NoError(t, err)
	stored, err := store.GetWitness(t.Context(), "anchor", pending[0].CheckpointSize)
	require.NoError(t, err)
	require.True(t, stored.Permanent)
	require.Equal(t, uint32(2), stored.Attempts)
}

func TestDeliveryRunnerVerifiesBeforeCompletion(t *testing.T) {
	store, now := pendingStore(t, []string{"anchor"})
	receipt := Receipt{Bytes: []byte("receipt"), EntryHash: string(bytes.Repeat([]byte{'0'}, 64)), EntryHashScheme: EntryHashSchemeCheckpointDigest, LeafIndex: 0, TreeSize: 1}
	runner, err := NewDeliveryRunner(DefaultDeliveryConfig(), store,
		map[string]Submitter{"anchor": fakeSubmitter{receipt: receipt}},
		map[string]Verifier{"anchor": fakeVerifier{}},
	)
	require.NoError(t, err)
	completed, err := runner.RunOnce(t.Context(), now, 1)
	require.NoError(t, err)
	require.Equal(t, 1, completed)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.NotNil(t, state.Witnesses[0].Receipt)
}

func TestDeliveryRunnerPersistsInvalidReceiptAsPermanent(t *testing.T) {
	store, now := pendingStore(t, []string{"anchor"})
	runner, err := NewDeliveryRunner(DefaultDeliveryConfig(), store,
		map[string]Submitter{"anchor": fakeSubmitter{}},
		map[string]Verifier{"anchor": fakeVerifier{err: errors.New("bad receipt")}},
	)
	require.NoError(t, err)
	_, err = runner.RunOnce(t.Context(), now, 1)
	require.NoError(t, err)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.True(t, state.Witnesses[0].Permanent)
	require.Contains(t, state.Witnesses[0].LastError, "bad receipt")
}

func TestDeliveryRunnerHandlesWitnessesIndependently(t *testing.T) {
	store, now := pendingStore(t, []string{"a", "b"})
	receipt := Receipt{Bytes: []byte("receipt"), EntryHashScheme: EntryHashSchemeCheckpointDigest, TreeSize: 1}
	runner, err := NewDeliveryRunner(DefaultDeliveryConfig(), store,
		map[string]Submitter{"a": fakeSubmitter{err: &HTTPError{StatusCode: http.StatusTooManyRequests}}, "b": fakeSubmitter{receipt: receipt}},
		map[string]Verifier{"a": fakeVerifier{}, "b": fakeVerifier{}},
	)
	require.NoError(t, err)
	completed, err := runner.RunOnce(t.Context(), now, 2)
	require.NoError(t, err)
	require.Equal(t, 1, completed)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	for _, item := range state.Witnesses {
		require.Equal(t, uint32(1), item.Attempts)
	}
}

func pendingStore(t *testing.T, witnessIDs []string) (*memory.Store, time.Time) {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := store.Append(t.Context(), cll.AppendInput{Value: bytes.Repeat([]byte{1}, cll.EntryBytes), AppendedAt: now})
	require.NoError(t, err)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := checkpoint.NewEd25519Signer(private)
	require.NoError(t, err)
	config := checkpoint.DefaultRunnerConfig("delivery-log")
	config.Cadence.CadenceEntries = 1
	config.WitnessIDs = witnessIDs
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)
	_, err = runner.RunOnce(t.Context(), now)
	require.NoError(t, err)
	state, err := store.LoadCLL(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, state.Witnesses)
	return store, state.Witnesses[0].NextAttemptAt
}
