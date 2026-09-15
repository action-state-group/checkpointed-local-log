package memory

import (
	"testing"

	"github.com/action-state-group/cll-go/internal/storetest"
)

func TestContract(t *testing.T) { storetest.Run(t, New()) }
