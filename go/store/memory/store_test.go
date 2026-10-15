package memory

import (
	"testing"

	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/cll/conformance"
	"github.com/action-state-group/checkpointed-local-log/go/internal/storetest"
)

var (
	_ cll.Backend    = (*Store)(nil)
	_ cll.EntryStore = (*Store)(nil)
)

func TestContract(t *testing.T) { storetest.Run(t, New()) }

func TestConformanceVectors(t *testing.T) {
	conformance.Run(t, conformance.Config{Open: func(*testing.T) any { return New() }})
}
