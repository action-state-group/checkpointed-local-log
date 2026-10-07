package mmr

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	dtmmr "github.com/datatrails/go-datatrails-merklelog/mmr"
)

// FileNodeStore is a durable, append-only MMR node store: a flat file of
// fixed 32-byte records, position = record index (byte offset = pos*32).
// This is the store a serving-path host should hold so its MMR survives a
// process restart without replaying the whole ledger to rebuild it -- Tree
// stays the in-memory representation proofs are computed against; load a
// Tree over everything a FileNodeStore holds with NewFromNodeStore. This is
// the Go sibling of the Rust cll crate's FileNodeStore, at parity on file
// format and crash-safety.
//
// Crash-safety: Append writes then fsyncs before returning, so a crash
// immediately afterward can leave at most one torn TRAILING record (a
// partial write of the last 32-byte chunk) -- never a torn record followed
// by a good one, since every completed append is durable before the next
// one starts. OpenFileNodeStore detects a torn tail (file length not a
// multiple of 32 bytes) and truncates it away, reporting how much was
// discarded; a torn record is never treated as a valid node.
type FileNodeStore struct {
	file      *os.File
	nodeCount uint64
}

// OpenReport is what OpenFileNodeStore found: how many whole 32-byte
// records are present, and how many trailing bytes (always < hashSize) were
// discarded as a torn record left by a crash between write and fsync.
type OpenReport struct {
	NodeCount      uint64
	TruncatedBytes uint64
}

// OpenFileNodeStore opens (creating if absent) the node file at path. A
// trailing partial record is truncated off and reported via OpenReport --
// never silently accepted as a valid node.
func OpenFileNodeStore(path string) (*FileNodeStore, OpenReport, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, OpenReport{}, fmt.Errorf("open MMR node file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, OpenReport{}, fmt.Errorf("stat MMR node file: %w", err)
	}
	length := uint64(info.Size())
	wholeRecords := length / hashSize
	truncatedBytes := length % hashSize
	if truncatedBytes != 0 {
		if err := file.Truncate(int64(wholeRecords * hashSize)); err != nil {
			_ = file.Close()
			return nil, OpenReport{}, fmt.Errorf("truncate torn MMR node file tail: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return nil, OpenReport{}, fmt.Errorf("sync truncated MMR node file: %w", err)
		}
	}
	return &FileNodeStore{file: file, nodeCount: wholeRecords}, OpenReport{NodeCount: wholeRecords, TruncatedBytes: truncatedBytes}, nil
}

// Close closes the underlying file.
func (s *FileNodeStore) Close() error {
	return s.file.Close()
}

// Size returns the number of complete 32-byte nodes currently stored.
func (s *FileNodeStore) Size() uint64 {
	return s.nodeCount
}

// Get implements dtmmr.NodeAppender's reader half.
func (s *FileNodeStore) Get(index uint64) ([]byte, error) {
	if index >= s.nodeCount {
		return nil, dtmmr.ErrNotFound
	}
	buffer := make([]byte, hashSize)
	if _, err := s.file.ReadAt(buffer, int64(index)*hashSize); err != nil {
		return nil, fmt.Errorf("read MMR node %d: %w", index, err)
	}
	return buffer, nil
}

// Append durably persists one node, fsyncing before returning so a crash
// immediately afterward can never leave a good record following a torn one.
func (s *FileNodeStore) Append(value []byte) (uint64, error) {
	if len(value) != hashSize {
		return 0, fmt.Errorf("MMR node must be exactly %d bytes", hashSize)
	}
	if _, err := s.file.WriteAt(value, int64(s.nodeCount)*hashSize); err != nil {
		return 0, fmt.Errorf("write MMR node %d: %w", s.nodeCount, err)
	}
	if err := s.file.Sync(); err != nil {
		return 0, fmt.Errorf("fsync MMR node file: %w", err)
	}
	s.nodeCount++
	return s.nodeCount, nil
}

// Nodes reads every complete node back in order, for handing to New to
// obtain a Tree that can compute proofs.
func (s *FileNodeStore) Nodes() ([][]byte, error) {
	nodes := make([][]byte, s.nodeCount)
	for index := range nodes {
		node, err := s.Get(uint64(index))
		if err != nil {
			return nil, err
		}
		nodes[index] = node
	}
	return nodes, nil
}

// NewFromNodeStore restores a Tree from every node currently in store, for
// proof computation over data a FileNodeStore already holds durably.
func NewFromNodeStore(store *FileNodeStore) (*Tree, error) {
	nodes, err := store.Nodes()
	if err != nil {
		return nil, err
	}
	return New(nodes)
}

// RebuildFileNodeStoreFromLeaves regenerates a fresh node file at path from
// an ordered sequence of already-appended CLL leaf body digests (the same
// values Tree.Append accepts) -- the recovery path when the node file at
// path is lost or judged untrustworthy. Overwrites any existing file at
// path; calling it twice with the same leaves produces byte-identical files
// (idempotent rebuild).
func RebuildFileNodeStoreFromLeaves(path string, leafBodyDigests [][]byte) (*FileNodeStore, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale MMR node file: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create MMR node file: %w", err)
	}
	store := &FileNodeStore{file: file}
	for _, value := range leafBodyDigests {
		if len(value) != hashSize {
			_ = store.Close()
			return nil, fmt.Errorf("CLL leaf value must be exactly %d bytes", hashSize)
		}
		leaf := sha256.Sum256(append([]byte{0}, value...))
		if _, err := dtmmr.AddHashedLeaf(store, sha256.New(), leaf[:]); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("rebuild MMR node file: %w", err)
		}
	}
	return store, nil
}
