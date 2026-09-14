package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/action-state-group/cll-go/checkpoint"
	"github.com/action-state-group/cll-go/cll"
	"github.com/action-state-group/cll-go/store/jsonl"
	"github.com/stretchr/testify/require"
)

// TestBoundedWitnessErrorSurvivesDurableReopen proves the end-to-end contract
// that a misbehaving witness cannot brick reopen. A LastError produced by
// boundedText from adversarial invalid UTF-8 is committed to a durable JSONL
// backend, which serializes it through encoding/json. Before the fix, the raw
// bytes grew past cll.MaxReasonBytes on that round-trip and reopen failed with
// "cll: corrupt: witness state is invalid". It must now reopen cleanly.
func TestBoundedWitnessErrorSurvivesDurableReopen(t *testing.T) {
	ctx := t.Context()
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	node := bytes.Repeat([]byte{3}, cll.EntryBytes)
	checkpointBytes := []byte("checkpoint")

	path := filepath.Join(t.TempDir(), "cll.jsonl")
	require.NoError(t, jsonl.Init(path))
	store, err := jsonl.Open(path)
	require.NoError(t, err)

	pending := cll.WitnessState{WitnessID: "primary", CheckpointSize: 1, Checkpoint: checkpointBytes, NextAttemptAt: at}
	state := cll.State{
		Size:       1,
		Nodes:      [][]byte{node},
		IndexedSeq: 1,
		Checkpoint: &cll.CheckpointState{Bytes: checkpointBytes, Size: 1, IndexedSeq: 1, Peaks: [][]byte{node}},
		Witnesses:  []cll.WitnessState{pending},
	}
	require.NoError(t, store.CommitCLL(ctx, 0, nil, state))

	row, err := store.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	failed := failedWitness(row, at, true, strings.Repeat("\xff", cll.MaxReasonBytes), time.Minute)
	require.LessOrEqual(t, len(failed.LastError), cll.MaxReasonBytes)
	require.NoError(t, store.CommitWitness(ctx, row.Attempts, failed))
	require.NoError(t, store.Close())

	reopened, err := jsonl.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	restored, err := reopened.GetWitness(ctx, "primary", 1)
	require.NoError(t, err)
	require.True(t, utf8.ValidString(restored.LastError))
	require.LessOrEqual(t, len(restored.LastError), cll.MaxReasonBytes)
	_, err = reopened.LoadCLL(ctx)
	require.NoError(t, err)
}

func TestBoundedTextIsValidUTF8AndWithinCapAcrossJSON(t *testing.T) {
	cases := map[string]string{
		"invalid utf8 over cap":  strings.Repeat("\xff", cll.MaxReasonBytes+128),
		"multibyte split at cap": strings.Repeat("€", cll.MaxReasonBytes/3+1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			bounded := boundedText(input)
			require.True(t, utf8.ValidString(bounded), "output must be valid UTF-8")
			require.LessOrEqual(t, len(bounded), cll.MaxReasonBytes)

			// A durable JSONL/SQL round-trip serializes LastError through
			// encoding/json. Valid UTF-8 must survive without growing past the
			// cap, otherwise reopen validation would reject it.
			encoded, err := json.Marshal(bounded)
			require.NoError(t, err)
			var decoded string
			require.NoError(t, json.Unmarshal(encoded, &decoded))
			require.Equal(t, bounded, decoded)
			require.LessOrEqual(t, len(decoded), cll.MaxReasonBytes)
		})
	}
}

func TestClientUsesCheckpointOnlyEndpoint(t *testing.T) {
	statement := checkpointStatement(t)
	record, err := checkpoint.ParseRecord(statement)
	require.NoError(t, err)
	entry, err := record.EntryHash()
	require.NoError(t, err)
	receiptB64 := base64.StdEncoding.EncodeToString([]byte("receipt"))
	entryHash := fmt.Sprintf("%x", entry)
	tests := []struct {
		name      string
		response  string
		wantError string
	}{
		{name: "current", response: fmt.Sprintf(`{"receipt_b64":%q,"entry_hash":%q,"entry_hash_scheme":"legacy","leaf_index":0,"tree_size":1,"future_field":"allowed"}`, receiptB64, entryHash)},
		{name: "missing scheme", response: fmt.Sprintf(`{"receipt_b64":%q,"entry_hash":%q,"leaf_index":0,"tree_size":1}`, receiptB64, entryHash), wantError: "unsupported entry hash scheme"},
		{name: "old statement scheme", response: fmt.Sprintf(`{"receipt_b64":%q,"entry_hash":%q,"entry_hash_scheme":"sig_structure","leaf_index":0,"tree_size":1}`, receiptB64, entryHash), wantError: "unsupported entry hash scheme"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				require.Equal(t, "/checkpoints", request.URL.Path)
				require.Equal(t, http.MethodPost, request.Method)
				require.Equal(t, checkpoint.ContentType, request.Header.Get("Content-Type"))
				require.Equal(t, "application/json", request.Header.Get("Accept"))
				body, err := io.ReadAll(request.Body)
				require.NoError(t, err)
				require.True(t, bytes.Equal(statement, body))
				writer.Header().Set("Content-Type", "application/json")
				_, err = writer.Write([]byte(test.response))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			client, err := NewClient(server.URL, server.Client(), 4096)
			require.NoError(t, err)
			receipt, err := client.Submit(t.Context(), statement)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, EntryHashSchemeCheckpointDigest, receipt.EntryHashScheme)
		})
	}
}

func TestClientRejectsRedirectOversizeAndInvalidPosition(t *testing.T) {
	statement := checkpointStatement(t)
	t.Run("redirect", func(t *testing.T) {
		followed := false
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/other" {
				followed = true
			}
			http.Redirect(writer, request, "/other", http.StatusFound)
		}))
		t.Cleanup(server.Close)
		client, err := NewClient(server.URL, server.Client(), 4096)
		require.NoError(t, err)
		_, err = client.Submit(t.Context(), statement)
		require.Error(t, err)
		require.False(t, followed)
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, err := writer.Write(make([]byte, 65))
			require.NoError(t, err)
		}))
		t.Cleanup(server.Close)
		client, err := NewClient(server.URL, server.Client(), 64)
		require.NoError(t, err)
		_, err = client.Submit(t.Context(), statement)
		require.ErrorContains(t, err, "exceeds")
	})

	t.Run("invalid position", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, err := fmt.Fprintf(writer, `{"receipt_b64":%q,"entry_hash":%q,"entry_hash_scheme":"legacy","leaf_index":1,"tree_size":1}`, base64.StdEncoding.EncodeToString([]byte("receipt")), fmt.Sprintf("%064x", 1))
			require.NoError(t, err)
		}))
		t.Cleanup(server.Close)
		client, err := NewClient(server.URL, server.Client(), 4096)
		require.NoError(t, err)
		_, err = client.Submit(t.Context(), statement)
		require.ErrorContains(t, err, "invalid transparency position")
	})
}

func TestClientClassifiesRetryableFailures(t *testing.T) {
	statement := checkpointStatement(t)
	status := http.StatusConflict
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { http.Error(writer, "failure", status) }))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, server.Client(), 4096)
	require.NoError(t, err)
	_, err = client.Submit(t.Context(), statement)
	require.False(t, IsRetryable(err))
	status = http.StatusTooManyRequests
	_, err = client.Submit(t.Context(), statement)
	require.True(t, IsRetryable(err))
}

func checkpointStatement(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := checkpoint.NewEd25519Signer(private)
	require.NoError(t, err)
	root := bytes.Repeat([]byte{0x02}, 32)
	payload, err := (checkpoint.Payload{
		LogID: "log", KeyID: signer.KeyID(), MMRSize: 1, Root: fmt.Sprintf("%x", root),
		Timestamp: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
	}).CanonicalJSON()
	require.NoError(t, err)
	statement, err := signer.SignCheckpoint(t.Context(), payload, [][]byte{root}, nil, nil)
	require.NoError(t, err)
	return statement
}
