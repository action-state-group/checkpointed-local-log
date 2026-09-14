package witness

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/internal/portable"
)

// Submitter sends a signed checkpoint to one witness.
type Submitter interface {
	Submit(context.Context, []byte) (Receipt, error)
}

// Verifier validates a receipt without trusting the submitting server.
type Verifier interface {
	Verify([]byte, Receipt) error
}

// DeliveryConfig controls the host-owned retry loop.
type DeliveryConfig struct {
	PollInterval time.Duration
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration
	Jitter       bool
}

// DefaultDeliveryConfig returns bounded exponential retry defaults.
func DefaultDeliveryConfig() DeliveryConfig {
	return DeliveryConfig{PollInterval: time.Minute, BaseBackoff: time.Second, MaxBackoff: time.Hour, Jitter: true}
}

// DeliveryRunner delivers pending checkpoints independently per witness.
type DeliveryRunner struct {
	config    DeliveryConfig
	store     cll.WitnessStateStore
	clients   map[string]Submitter
	verifiers map[string]Verifier
	notify    chan struct{}
	mu        sync.Mutex
}

// NewDeliveryRunner validates dependencies without starting background work.
func NewDeliveryRunner(config DeliveryConfig, store cll.WitnessStateStore, clients map[string]Submitter, verifiers map[string]Verifier) (*DeliveryRunner, error) {
	if config.PollInterval <= 0 || config.BaseBackoff <= 0 || config.MaxBackoff < config.BaseBackoff || store == nil || len(clients) == 0 || len(clients) > cll.MaxWitnesses || len(verifiers) != len(clients) {
		return nil, fmt.Errorf("%w: invalid witness delivery configuration", cll.ErrInvalid)
	}
	clientCopy := make(map[string]Submitter, len(clients))
	verifierCopy := make(map[string]Verifier, len(verifiers))
	for id, client := range clients {
		verifier := verifiers[id]
		if cll.ValidateIdentifier(id) != nil || client == nil || verifier == nil {
			return nil, fmt.Errorf("%w: invalid witness dependency for %q", cll.ErrInvalid, id)
		}
		clientCopy[id], verifierCopy[id] = client, verifier
	}
	return &DeliveryRunner{config: config, store: store, clients: clientCopy, verifiers: verifierCopy, notify: make(chan struct{}, 1)}, nil
}

// Notify wakes a running delivery loop without blocking the caller.
func (r *DeliveryRunner) Notify() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Run delivers until the host cancels the context.
func (r *DeliveryRunner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()
	for {
		if _, err := r.RunOnce(ctx, time.Now().UTC(), cll.MaxWitnesses); err != nil && !errors.Is(err, cll.ErrContention) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.notify:
		case <-ticker.C:
		}
	}
}

// RunOnce processes due rows concurrently across witnesses and sequentially
// within each witness. A retryable failure stops that witness's current pass.
func (r *DeliveryRunner) RunOnce(ctx context.Context, now time.Time, limit int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now = portable.NormalizeTime(now)
	pending, err := r.store.PendingWitnesses(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	groups := make(map[string][]cll.WitnessState)
	for _, item := range pending {
		groups[item.WitnessID] = append(groups[item.WitnessID], item)
	}
	type outcome struct {
		completed int
		err       error
	}
	results := make(chan outcome, len(groups))
	var wait sync.WaitGroup
	for id, items := range groups {
		id, items := id, items
		wait.Add(1)
		go func() {
			defer wait.Done()
			completed := 0
			for _, item := range items {
				success, retryable, err := r.deliver(ctx, now, id, item)
				if err != nil {
					results <- outcome{completed: completed, err: err}
					return
				}
				if success {
					completed++
				}
				if retryable {
					break
				}
			}
			results <- outcome{completed: completed}
		}()
	}
	wait.Wait()
	close(results)
	completed := 0
	for result := range results {
		completed += result.completed
		if result.err != nil {
			return completed, result.err
		}
	}
	return completed, nil
}

func (r *DeliveryRunner) deliver(ctx context.Context, now time.Time, id string, item cll.WitnessState) (bool, bool, error) {
	client, clientOK := r.clients[id]
	verifier, verifierOK := r.verifiers[id]
	if !clientOK || !verifierOK {
		return false, false, fmt.Errorf("%w: no configured client and verifier for witness %q", cll.ErrInvalid, id)
	}
	record, err := checkpoint.ParseRecord(item.Checkpoint)
	if err != nil || record.VerifySignature() != nil {
		next := failedWitness(item, now, true, "stored checkpoint failed verification", r.backoff(item.Attempts))
		return false, false, r.store.CommitWitness(ctx, item.Attempts, next)
	}
	receipt, err := client.Submit(ctx, item.Checkpoint)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, false, ctxErr
	}
	if err != nil {
		retryable := IsRetryable(err)
		next := failedWitness(item, now, !retryable, err.Error(), r.backoff(item.Attempts))
		return false, retryable, r.store.CommitWitness(ctx, item.Attempts, next)
	}
	if err := verifier.Verify(item.Checkpoint, receipt); err != nil {
		next := failedWitness(item, now, true, err.Error(), r.backoff(item.Attempts))
		return false, false, r.store.CommitWitness(ctx, item.Attempts, next)
	}
	leafIndex, treeSize := receipt.LeafIndex, receipt.TreeSize
	next := item
	next.Attempts++
	next.NextAttemptAt = now
	next.Receipt = &cll.WitnessReceiptState{Bytes: append([]byte(nil), receipt.Bytes...), EntryHash: receipt.EntryHash, EntryHashScheme: receipt.EntryHashScheme, LeafIndex: &leafIndex, TreeSize: &treeSize}
	next.Permanent = false
	next.LastError = ""
	return true, false, r.store.CommitWitness(ctx, item.Attempts, next)
}

func failedWitness(item cll.WitnessState, now time.Time, permanent bool, reason string, delay time.Duration) cll.WitnessState {
	item.Attempts++
	item.Permanent = permanent
	item.LastError = boundedText(reason)
	item.NextAttemptAt = now.Add(delay)
	return item
}

func (r *DeliveryRunner) backoff(attempts uint32) time.Duration {
	delay := r.config.BaseBackoff
	for count := uint32(0); count < attempts && delay < r.config.MaxBackoff; count++ {
		if delay > r.config.MaxBackoff-delay {
			delay = r.config.MaxBackoff
		} else {
			delay *= 2
		}
	}
	if r.config.Jitter && delay > 0 {
		delay = time.Duration(rand.Int64N(int64(delay)))
	}
	return delay
}
