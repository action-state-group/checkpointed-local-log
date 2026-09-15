package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/mmr"
	"github.com/action-state-group/cll-go/store/jsonl"
	"github.com/action-state-group/cll-go/store/mysql"
	"github.com/action-state-group/cll-go/store/sqlite"
)

const witnessID = "interop-witness"

var baseTime = time.Date(2026, 9, 3, 12, 0, 0, 123_000_000, time.UTC)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		panic(err)
	}
}

func run(ctx context.Context, args []string) (runErr error) {
	if len(args) < 4 {
		return fmt.Errorf("usage: storage <advance|verify|hold|expect-contention> <jsonl|sqlite|mysql> <target> <log-id> [argument]")
	}
	mode, backendName, target, logID := args[0], args[1], args[2], args[3]
	if mode == "advance" || mode == "hold" {
		var err error
		switch backendName {
		case "mysql":
			err = mysql.Init(ctx, target, logID)
		case "sqlite":
			err = sqlite.Init(target, logID)
		case "jsonl":
			err = jsonl.Init(target)
		}
		if err != nil {
			return err
		}
	}

	if mode == "expect-contention" {
		store, err := openBackend(ctx, backendName, target, logID)
		if err == nil {
			if closeErr := store.Close(); closeErr != nil {
				return fmt.Errorf("second writer opened and close failed: %w", closeErr)
			}
			return fmt.Errorf("second writer unexpectedly opened")
		}
		if !errors.Is(err, cll.ErrContention) {
			return fmt.Errorf("expected contention, got %w", err)
		}
		return nil
	}

	store, err := openBackend(ctx, backendName, target, logID)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, store.Close())
	}()

	switch mode {
	case "advance":
		return advance(ctx, store)
	case "verify":
		if len(args) != 5 {
			return fmt.Errorf("verify requires expected entry count")
		}
		expected, parseErr := strconv.Atoi(args[4])
		if parseErr != nil {
			return parseErr
		}
		return verify(ctx, store, expected)
	case "hold":
		if len(args) != 6 {
			return fmt.Errorf("hold requires ready and stop paths")
		}
		return hold(args[4], args[5])
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func openBackend(ctx context.Context, backendName, target, logID string) (cll.Backend, error) {
	switch backendName {
	case "jsonl":
		return jsonl.Open(target)
	case "sqlite":
		return sqlite.Open(target, logID)
	case "mysql":
		return mysql.Open(ctx, target, logID)
	default:
		return nil, fmt.Errorf("unsupported backend %q", backendName)
	}
}

func advance(ctx context.Context, store cll.Backend) error {
	entries, err := store.ScanEntries(ctx, 0, cll.MaxScanLimit)
	if err != nil {
		return err
	}
	if err := verify(ctx, store, len(entries)); err != nil {
		return fmt.Errorf("verify before advance: %w", err)
	}
	sequence := len(entries) + 1
	if sequence > 255 {
		return fmt.Errorf("interop sequence exceeds fixture range")
	}
	identity := identityFor(sequence)
	result, err := store.Append(ctx, cll.AppendInput{
		Value:      identity,
		AppendedAt: timeFor(sequence),
	})
	if err != nil {
		return err
	}
	if result.Outcome != cll.AppendInserted || result.Entry.Seq != uint64(sequence) {
		return fmt.Errorf("unexpected append result: %+v", result)
	}

	state, err := store.LoadCLL(ctx)
	if err != nil {
		return err
	}
	tree, err := mmr.New(state.Nodes)
	if err != nil {
		return err
	}
	if _, err := tree.Append(identity); err != nil {
		return err
	}
	peaks, err := tree.PeakHashesAt(tree.Size())
	if err != nil {
		return err
	}
	checkpointBytes := checkpointFor(sequence)
	previous := state.Checkpoint
	var expectedCheckpoint []byte
	if previous != nil {
		expectedCheckpoint = append([]byte(nil), previous.Bytes...)
	}
	next := state
	next.Size = tree.Size()
	next.Nodes = tree.Nodes()
	next.IndexedSeq = uint64(sequence)
	next.Checkpoint = &cll.CheckpointState{
		Bytes:      checkpointBytes,
		Size:       tree.Size(),
		IndexedSeq: uint64(sequence),
		Peaks:      peaks,
	}
	next.Witnesses = append(next.Witnesses, cll.WitnessState{
		WitnessID:      witnessID,
		CheckpointSize: tree.Size(),
		Checkpoint:     checkpointBytes,
		NextAttemptAt:  timeFor(sequence),
	})
	if err := store.CommitCLL(ctx, state.Size, expectedCheckpoint, next); err != nil {
		return err
	}
	if previous != nil {
		if err := completeWitness(ctx, store, previous.Size, sequence-1, sequence); err != nil {
			return err
		}
	}
	return verify(ctx, store, sequence)
}

func completeWitness(ctx context.Context, store cll.Backend, checkpointSize uint64, checkpointSequence, currentSequence int) error {
	current, err := store.GetWitness(ctx, witnessID, checkpointSize)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(current.Checkpoint)
	leafIndex := int64(checkpointSequence - 1)
	treeSize := int64(currentSequence)
	current.Attempts++
	current.NextAttemptAt = timeFor(currentSequence)
	current.Receipt = &cll.WitnessReceiptState{
		Bytes:           receiptFor(checkpointSequence),
		EntryHash:       hex.EncodeToString(digest[:]),
		EntryHashScheme: "legacy",
		LeafIndex:       &leafIndex,
		TreeSize:        &treeSize,
	}
	return store.CommitWitness(ctx, current.Attempts-1, current)
}

func verify(ctx context.Context, store cll.Backend, expected int) error {
	entries, err := store.ScanEntries(ctx, 0, cll.MaxScanLimit)
	if err != nil {
		return err
	}
	if len(entries) != expected {
		return fmt.Errorf("got %d entries, want %d", len(entries), expected)
	}
	tree, err := mmr.New(nil)
	if err != nil {
		return err
	}
	sizes := make([]uint64, 0, expected)
	for sequence, entry := range entries {
		wantSequence := sequence + 1
		if entry.Seq != uint64(wantSequence) || !bytes.Equal(entry.Value, identityFor(wantSequence)) || !entry.AppendedAt.Equal(timeFor(wantSequence)) {
			return fmt.Errorf("entry %d disagrees with portable fixture", wantSequence)
		}
		if _, err := tree.Append(entry.Value); err != nil {
			return err
		}
		sizes = append(sizes, tree.Size())
	}

	state, err := store.LoadCLL(ctx)
	if err != nil {
		return err
	}
	if state.Size != tree.Size() || state.IndexedSeq != uint64(expected) || !sameList(state.Nodes, tree.Nodes()) || len(state.Witnesses) != expected || state.FirstPendingAt != nil {
		return fmt.Errorf("CLL state disagrees with portable fixture")
	}
	if expected == 0 {
		if state.Checkpoint != nil {
			return fmt.Errorf("empty fixture has a checkpoint")
		}
		return nil
	}
	peaks, err := tree.PeakHashesAt(tree.Size())
	if err != nil {
		return err
	}
	if state.Checkpoint == nil || state.Checkpoint.Size != tree.Size() || state.Checkpoint.IndexedSeq != uint64(expected) || !bytes.Equal(state.Checkpoint.Bytes, checkpointFor(expected)) || !sameList(state.Checkpoint.Peaks, peaks) {
		return fmt.Errorf("latest checkpoint disagrees with portable fixture")
	}
	for sequence, size := range sizes {
		checkpointSequence := sequence + 1
		item, err := store.GetWitness(ctx, witnessID, size)
		if err != nil {
			return err
		}
		if !bytes.Equal(item.Checkpoint, checkpointFor(checkpointSequence)) {
			return fmt.Errorf("witness %d checkpoint mismatch", checkpointSequence)
		}
		if checkpointSequence == expected {
			if item.Attempts != 0 || item.Receipt != nil {
				return fmt.Errorf("latest witness is not pending")
			}
			continue
		}
		if err := verifyReceipt(item, checkpointSequence); err != nil {
			return err
		}
	}
	pending, err := store.PendingWitnesses(ctx, baseTime.Add(24*time.Hour), cll.MaxWitnesses)
	if err != nil {
		return err
	}
	if len(pending) != 1 || pending[0].CheckpointSize != sizes[len(sizes)-1] {
		return fmt.Errorf("pending witness projection mismatch")
	}
	return nil
}

func verifyReceipt(item cll.WitnessState, checkpointSequence int) error {
	digest := sha256.Sum256(checkpointFor(checkpointSequence))
	if item.Attempts != 1 || item.Receipt == nil || !bytes.Equal(item.Receipt.Bytes, receiptFor(checkpointSequence)) || item.Receipt.EntryHash != hex.EncodeToString(digest[:]) || item.Receipt.EntryHashScheme != "legacy" || item.Receipt.LeafIndex == nil || *item.Receipt.LeafIndex != int64(checkpointSequence-1) || item.Receipt.TreeSize == nil || *item.Receipt.TreeSize != int64(checkpointSequence+1) {
		return fmt.Errorf("witness %d receipt mismatch", checkpointSequence)
	}
	return nil
}

func identityFor(sequence int) []byte {
	return bytes.Repeat([]byte{byte(sequence)}, cll.EntryBytes)
}

func checkpointFor(sequence int) []byte {
	return []byte{0xc0, byte(sequence)}
}

func receiptFor(sequence int) []byte {
	return []byte{0xd0, byte(sequence)}
}

func timeFor(sequence int) time.Time {
	return baseTime.Add(time.Duration(sequence) * time.Second)
}

func sameList(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func hold(readyPath, stopPath string) error {
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		return err
	}
	deadline := time.NewTimer(time.Minute)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for stop file")
		case <-ticker.C:
			if _, err := os.Stat(stopPath); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
}
