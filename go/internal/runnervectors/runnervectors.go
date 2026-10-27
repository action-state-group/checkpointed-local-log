// Package runnervectors builds and replays the shared checkpoint and witness
// runner vectors (runner-conformance-vectors/ at the repository root).
//
// The Go runners are the reference: Build runs each scenario against a fresh
// memory backend and records what the Go checkpoint.Runner and
// witness.DeliveryRunner leave in durable state; Replay runs a document's
// scenarios again and reports the first difference. The other languages
// replay the same document with their own runners.
package runnervectors

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/internal/backend"
	"github.com/action-state-group/checkpointed-local-log/go/store/memory"
	"github.com/action-state-group/checkpointed-local-log/go/witness"
)

// LastErrorMarker replaces every stored lastError: its text is each
// language's own, so the vectors pin only whether it is set.
const LastErrorMarker = "<set>"

// Document is the vectors file.
type Document struct {
	Version        int               `json:"version"`
	Description    string            `json:"description"`
	SigningKeySeed string            `json:"signingKeySeed"`
	LogID          string            `json:"logId"`
	Capabilities   map[string]string `json:"capabilities"`
	Cases          []Case            `json:"cases"`
}

// Case is one scenario against a fresh, empty backend.
type Case struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Requires    []string `json:"requires,omitempty"`
	Config      Config   `json:"config"`
	Steps       []Step   `json:"steps"`
}

// Config configures both runners for a case.
type Config struct {
	CadenceEntries uint64   `json:"cadenceEntries"`
	CadenceAgeMs   int64    `json:"cadenceAgeMs"`
	ScanLimit      int      `json:"scanLimit"`
	WitnessIDs     []string `json:"witnessIds"`
	BaseBackoffMs  int64    `json:"baseBackoffMs"`
	MaxBackoffMs   int64    `json:"maxBackoffMs"`
}

// Step is one operation. append adds an entry to the backend; runCheckpoint
// is one checkpoint runner pass; deliverWitnesses is one delivery pass whose
// witnesses answer from Submit and Verify, in order; loadCll reads the state.
type Step struct {
	Op         string               `json:"op"`
	Value      string               `json:"value,omitempty"`
	AppendedAt string               `json:"appendedAt,omitempty"`
	Now        string               `json:"now,omitempty"`
	Limit      int                  `json:"limit,omitempty"`
	Submit     map[string][]Outcome `json:"submit,omitempty"`
	Verify     map[string][]bool    `json:"verify,omitempty"`
	Expect     *Expect              `json:"expect,omitempty"`
}

// Outcome is a scripted witness answer: a receipt, or an error that is
// "retryable" or "permanent".
type Outcome struct {
	Receipt *Receipt `json:"receipt,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Receipt is a scripted receipt in the backend's portable field names.
type Receipt struct {
	Bytes           string `json:"bytes"`
	EntryHash       string `json:"entryHash"`
	EntryHashScheme string `json:"entryHashScheme"`
	LeafIndex       int64  `json:"leafIndex"`
	TreeSize        int64  `json:"treeSize"`
}

// Expect is a step's expected result.
type Expect struct {
	Result json.RawMessage `json:"result"`
}

// Build runs every scenario with the Go runners and returns the document with
// each loadCll and deliverWitnesses result filled in.
func Build() (Document, error) {
	document := Document{
		Version: 1,
		Description: "Checkpoint and witness runner cases. Each case runs its steps in order against a fresh, empty " +
			"backend with the case's runner configuration. Times and bytes use the backend contract's portable " +
			"encodings; loadCll results are in its portable state form, with witnesses sorted by checkpointSize " +
			"then witnessId and every lastError replaced by \"" + LastErrorMarker + "\".",
		SigningKeySeed: hex.EncodeToString(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)),
		LogID:          "runner-vectors",
		Capabilities: map[string]string{
			"bounded-run":          "a checkpoint pass scans one batch of scanLimit entries and checkpoints it when due",
			"stop-after-retryable": "a retryable failure ends that witness's delivery pass",
		},
		Cases: scenarios(),
	}
	for index := range document.Cases {
		if err := run(context.Background(), document, &document.Cases[index], true); err != nil {
			return Document{}, fmt.Errorf("%s: %w", document.Cases[index].Name, err)
		}
	}
	return document, nil
}

// Replay runs every case of document with the Go runners and returns the
// first result that differs from the document.
func Replay(ctx context.Context, document Document) error {
	for index := range document.Cases {
		item := document.Cases[index]
		if err := run(ctx, document, &item, false); err != nil {
			return fmt.Errorf("%s: %w", item.Name, err)
		}
	}
	return nil
}

func run(ctx context.Context, document Document, item *Case, record bool) error {
	seed, err := hex.DecodeString(document.SigningKeySeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid signing key seed")
	}
	signer, err := checkpoint.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return err
	}
	store := memory.New()
	config := checkpoint.DefaultRunnerConfig(document.LogID)
	config.Cadence = checkpoint.Config{CadenceEntries: item.Config.CadenceEntries, CadenceAge: time.Duration(item.Config.CadenceAgeMs) * time.Millisecond}
	config.ScanLimit = item.Config.ScanLimit
	config.WitnessIDs = item.Config.WitnessIDs
	runner, err := checkpoint.NewRunner(config, store, signer)
	if err != nil {
		return err
	}
	script := &script{}
	clients := make(map[string]witness.Submitter)
	verifiers := make(map[string]witness.Verifier)
	for _, id := range item.Config.WitnessIDs {
		clients[id] = scriptedSubmitter{script: script, id: id}
		verifiers[id] = scriptedVerifier{script: script, id: id}
	}
	// A delivery runner needs at least one witness; cases without one never deliver.
	var delivery *witness.DeliveryRunner
	if len(clients) > 0 {
		delivery, err = witness.NewDeliveryRunner(witness.DeliveryConfig{
			PollInterval: time.Minute,
			BaseBackoff:  time.Duration(item.Config.BaseBackoffMs) * time.Millisecond,
			MaxBackoff:   time.Duration(item.Config.MaxBackoffMs) * time.Millisecond,
		}, store, clients, verifiers)
		if err != nil {
			return err
		}
	}
	for index := range item.Steps {
		step := &item.Steps[index]
		var result any
		switch step.Op {
		case "append":
			value, err := base64.StdEncoding.DecodeString(step.Value)
			if err != nil {
				return err
			}
			at, err := time.Parse(time.RFC3339Nano, step.AppendedAt)
			if err != nil {
				return err
			}
			if _, err := store.Append(ctx, cll.AppendInput{Value: value, AppendedAt: at}); err != nil {
				return err
			}
			continue
		case "runCheckpoint":
			now, err := time.Parse(time.RFC3339Nano, step.Now)
			if err != nil {
				return err
			}
			if _, err := runner.RunOnce(ctx, now); err != nil {
				return fmt.Errorf("step %d: %w", index, err)
			}
			continue
		case "deliverWitnesses":
			now, err := time.Parse(time.RFC3339Nano, step.Now)
			if err != nil {
				return err
			}
			if delivery == nil {
				return fmt.Errorf("step %d: deliverWitnesses needs a witness", index)
			}
			script.load(step)
			completed, err := delivery.RunOnce(ctx, now, step.Limit)
			if err != nil {
				return fmt.Errorf("step %d: %w", index, err)
			}
			if err := script.exhausted(); err != nil {
				return fmt.Errorf("step %d: %w", index, err)
			}
			result = completed
		case "loadCll":
			state, err := store.LoadCLL(ctx)
			if err != nil {
				return err
			}
			if result, err = Normalize(state); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown op %q", step.Op)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if record {
			step.Expect = &Expect{Result: encoded}
			continue
		}
		if step.Expect == nil || !jsonEqual(step.Expect.Result, encoded) {
			return fmt.Errorf("step %d (%s): got %s", index, step.Op, encoded)
		}
	}
	return nil
}

// Normalize returns state in the vectors' comparable form: witnesses sorted
// by numeric checkpointSize, then witnessId, and lastError replaced by
// LastErrorMarker.
func Normalize(state cll.State) (backend.WireState, error) {
	wire, err := backend.StateToWire(state)
	if err != nil {
		return backend.WireState{}, err
	}
	slices.SortFunc(wire.Witnesses, func(a, b backend.WireWitness) int {
		left, _ := strconv.ParseUint(a.CheckpointSize, 10, 64)
		right, _ := strconv.ParseUint(b.CheckpointSize, 10, 64)
		return cmp.Or(cmp.Compare(left, right), strings.Compare(a.WitnessID, b.WitnessID))
	})
	for index := range wire.Witnesses {
		if wire.Witnesses[index].LastError != "" {
			wire.Witnesses[index].LastError = LastErrorMarker
		}
	}
	return wire, nil
}

func jsonEqual(left, right []byte) bool {
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// script serves each witness's scripted answers in order. The delivery
// runner calls witnesses concurrently, so access is locked.
type script struct {
	mu     sync.Mutex
	submit map[string][]Outcome
	verify map[string][]bool
}

func (s *script) next(id string) (Outcome, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outcomes := s.submit[id]
	if len(outcomes) == 0 {
		return Outcome{}, false
	}
	s.submit[id] = outcomes[1:]
	return outcomes[0], true
}

func (s *script) answer(id string) (accepted, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	answers := s.verify[id]
	if len(answers) == 0 {
		return false, false
	}
	s.verify[id] = answers[1:]
	return answers[0], true
}

func (s *script) load(step *Step) {
	s.submit, s.verify = map[string][]Outcome{}, map[string][]bool{}
	for id, outcomes := range step.Submit {
		s.submit[id] = append([]Outcome(nil), outcomes...)
	}
	for id, answers := range step.Verify {
		s.verify[id] = append([]bool(nil), answers...)
	}
}

func (s *script) exhausted() error {
	for id, outcomes := range s.submit {
		if len(outcomes) != 0 {
			return fmt.Errorf("witness %s left %d submit outcomes unused", id, len(outcomes))
		}
	}
	for id, answers := range s.verify {
		if len(answers) != 0 {
			return fmt.Errorf("witness %s left %d verify answers unused", id, len(answers))
		}
	}
	return nil
}

type scriptedSubmitter struct {
	script *script
	id     string
}

func (s scriptedSubmitter) Submit(context.Context, []byte) (witness.Receipt, error) {
	outcome, ok := s.script.next(s.id)
	if !ok {
		return witness.Receipt{}, fmt.Errorf("witness %s submitted more than scripted", s.id)
	}
	switch {
	case outcome.Error == "retryable":
		return witness.Receipt{}, &witness.HTTPError{StatusCode: http.StatusServiceUnavailable, Body: "scripted retryable failure"}
	case outcome.Error == "permanent":
		return witness.Receipt{}, &witness.HTTPError{StatusCode: http.StatusBadRequest, Body: "scripted permanent failure"}
	case outcome.Receipt != nil:
		raw, err := base64.StdEncoding.DecodeString(outcome.Receipt.Bytes)
		if err != nil {
			return witness.Receipt{}, err
		}
		return witness.Receipt{Bytes: raw, EntryHash: outcome.Receipt.EntryHash, EntryHashScheme: outcome.Receipt.EntryHashScheme, LeafIndex: outcome.Receipt.LeafIndex, TreeSize: outcome.Receipt.TreeSize}, nil
	}
	return witness.Receipt{}, errors.New("invalid scripted outcome")
}

type scriptedVerifier struct {
	script *script
	id     string
}

func (s scriptedVerifier) Verify([]byte, witness.Receipt) error {
	accepted, ok := s.script.answer(s.id)
	if !ok {
		return fmt.Errorf("witness %s verified more than scripted", s.id)
	}
	if !accepted {
		return errors.New("scripted receipt rejection")
	}
	return nil
}
