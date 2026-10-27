// Command runnervectors writes runner-conformance-vectors/vectors.json and
// its pinned copies from the Go runners, or with -check fails if any
// committed copy differs. Run it from the go/ directory:
//
//	go run ./test/runnervectors
//	go run ./test/runnervectors -check
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/action-state-group/checkpointed-local-log/go/internal/runnervectors"
)

// targets are relative to the repository root. Each implementation that
// cannot read the repository root at test time reads its own copy.
var targets = []string{
	"runner-conformance-vectors/vectors.json",
	"go/internal/runnervectors/testdata/vectors.json",
	"ts/test/testdata/runner-vectors.json",
}

func main() {
	check := flag.Bool("check", false, "fail if a committed copy differs")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(check bool) error {
	document, err := runnervectors.Build()
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(document, "", " ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	for _, target := range targets {
		path := filepath.Join("..", target)
		if check {
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(current, encoded) {
				return fmt.Errorf("stale runner vectors: %s; run go run ./test/runnervectors", target)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			return err
		}
	}
	return nil
}
