package runnervectors_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/internal/runnervectors"
	"github.com/stretchr/testify/require"
)

// testdata/vectors.json is the pinned copy of
// runner-conformance-vectors/vectors.json; go run ./test/runnervectors -check
// keeps them identical.
func TestGoRunnersReplayTheVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err)
	var document runnervectors.Document
	require.NoError(t, json.Unmarshal(raw, &document))
	require.NotEmpty(t, document.Cases)
	require.NoError(t, runnervectors.Replay(t.Context(), document))
}

func TestReplayReportsADifference(t *testing.T) {
	document, err := runnervectors.Build()
	require.NoError(t, err)
	last := &document.Cases[1].Steps[len(document.Cases[1].Steps)-1]
	last.Expect.Result = json.RawMessage(`{"size":"0"}`)
	require.ErrorContains(t, runnervectors.Replay(t.Context(), document), "checkpoint/entry-cadence")
}
