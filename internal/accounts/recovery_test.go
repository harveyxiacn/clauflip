package accounts

import (
	"encoding/json"
	"errors"
	"testing"
)

// Simulates a native credential backend whose ordinary reader refuses a split
// generation, but can reconcile only a known journal before/after pair.
type splitStore struct {
	memoryCredentials
	split, called bool
}

func (s *splitStore) Read() ([]byte, error) {
	if s.split {
		return nil, errors.New("split credential generation")
	}
	return s.memoryCredentials.Read()
}
func (s *splitStore) RecoverAccount(before, after []byte) error {
	s.called = true
	s.split = false
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(before, &fields); err != nil {
		return err
	}
	// A missing device token must stay missing, not become JSON null.
	if v, ok := fields["trustedDeviceToken"]; ok && string(v) == "null" {
		return errors.New("null device token supplied")
	}
	s.data = before
	return nil
}
func TestRecoveryReconcilesNativeBackendBeforeCapture(t *testing.T) {
	e, c := fixture(t)
	setLive(t, e, c, "a", "a", false)
	must(t, e.Save("personal"))
	before, _ := e.capture()
	setLive(t, e, c, "b", "b", true)
	must(t, e.Save("work"))
	after, _ := e.capture()
	must(t, e.writeJSON(e.journalPath(), journal{Version: 1, Before: before, After: after, ActiveBefore: "personal", ActiveAfter: "work"}))
	store := &splitStore{memoryCredentials: *c, split: true}
	e.Credentials = store
	must(t, e.Recover())
	if !store.called {
		t.Fatal("native reconciliation skipped")
	}
	got, err := e.capture()
	must(t, err)
	if !sameAccountFields(got, before) {
		t.Fatal("wrong generation after native recovery")
	}
}
func TestRecoveryDoesNotReconcileCredentialsWhenIdentityIsNewer(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before, _ := e.capture()
	setLive(t, e, c, "b", "b", false)
	must(t, e.Save("work"))
	after, _ := e.capture()
	must(t, e.writeJSON(e.journalPath(), journal{Version: 1, Before: before, After: after, ActiveBefore: "personal", ActiveAfter: "work"}))
	setLive(t, e, c, "c", "new-external-login", false)
	store := &splitStore{memoryCredentials: *c, split: true}
	e.Credentials = store
	if e.Recover() == nil {
		t.Fatal("external login must block recovery")
	}
	if store.called {
		t.Fatal("reconciled credentials before validating identity")
	}
}
