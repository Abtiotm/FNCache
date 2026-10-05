package ownership

import (
	"encoding/json"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func FuzzOwnershipStateValidation(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"schemaVersion":1,"installationID":"install-a","nodeUID":"node-a"}`),
		[]byte(`{"schemaVersion":2,"installationID":"install-a","nodeUID":"node-a"}`),
		[]byte(`null`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var state reconcile.OwnershipState
		if err := json.Unmarshal(data, &state); err != nil {
			return
		}
		_ = validateState(state)
	})
}
