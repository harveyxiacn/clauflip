package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedReloginRecoversNewCredentials(t *testing.T) {
	for _, failure := range []string{"credentials", "identity", "preflight"} {
		t.Run(failure, func(t *testing.T) {
			e, c := fixture(t)
			must(t, e.Save("personal"))
			fakeLogin(t, e, "a", false)
			settings := filepath.Join(e.Paths.ConfigDir, "settings.json")
			must(t, os.WriteFile(settings, []byte(`{"hooks":{"keep":true},"env":{"keep":"value"}}`), 0600))
			settingsBefore := read(t, settings)
			credentialsBefore := rawMap(t, c.data)
			identityBefore := rawMap(t, read(t, e.Paths.IdentityFile))
			original := e.WriteFile
			switch failure {
			case "credentials":
				c.fail = true
			case "identity":
				e.WriteFile = func(path string, b []byte, mode os.FileMode) error {
					if path == e.Paths.IdentityFile {
						return errors.New("disk full")
					}
					return original(path, b, mode)
				}
			case "preflight":
				checks := 0
				e.CheckIdle = func() error {
					checks++
					if checks > 1 {
						return errors.New("Claude started")
					}
					return nil
				}
			}
			err := e.Login("personal")
			if err == nil || !strings.Contains(err.Error(), "recover") || strings.Contains(err.Error(), "previous account restored") {
				t.Fatalf("missing pending activation message: %v", err)
			}
			if _, err := os.Stat(e.journalPath()); err != nil {
				t.Fatal("new login not retained in recovery journal", err)
			}
			if e.Use("personal") == nil || e.Save("personal") == nil {
				t.Fatal("pending relogin allowed old-token overwrite")
			}
			c.fail = false
			e.WriteFile = original
			e.CheckIdle = func() error { return nil }
			must(t, e.Recover())
			must(t, e.Recover())
			must(t, e.Use("personal"))
			must(t, e.Save("personal"))
			live, err := e.capture()
			must(t, err)
			s, err := e.loadState()
			must(t, err)
			if !bytes.Contains(live.OAuth, []byte("new-login-a")) || !sameAccountFields(live, s.Accounts["personal"]) {
				t.Fatal("new credentials lost after recovery/use/save")
			}
			if !bytes.Equal(settingsBefore, read(t, settings)) {
				t.Fatal("settings changed")
			}
			afterCredentials := rawMap(t, c.data)
			for _, k := range []string{"mcpOAuth", "pluginSecrets"} {
				if !equalJSON(credentialsBefore[k], afterCredentials[k]) {
					t.Fatal("credential sibling changed", k)
				}
			}
			afterIdentity := rawMap(t, read(t, e.Paths.IdentityFile))
			for _, k := range []string{"projects", "largeInteger", "theme"} {
				if !equalJSON(identityBefore[k], afterIdentity[k]) {
					t.Fatal("identity sibling changed", k)
				}
			}
		})
	}
}

func TestReloginRecoveryNativeBackendFinishesNewGeneration(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before, _ := e.capture()
	setLive(t, e, c, "a", "new-login-a", false)
	after, _ := e.capture()
	must(t, e.writeJSON(e.journalPath(), journal{Version: 1, Before: before, After: after, ActiveBefore: "personal", ActiveAfter: "personal"}))
	store := &splitStore{memoryCredentials: *c, split: true}
	e.Credentials = store
	must(t, e.Recover())
	must(t, e.Use("personal"))
	got, err := e.capture()
	must(t, err)
	if !store.called || !sameAccountFields(got, after) {
		t.Fatal("native recovery discarded refreshed generation")
	}
}

func TestReloginJournalMismatchedIdentityCannotWrite(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before, _ := e.capture()
	setLive(t, e, c, "b", "b", false)
	after, _ := e.capture()
	credentials := bytes.Clone(c.data)
	identity := read(t, e.Paths.IdentityFile)
	j := journal{Version: 1, Before: before, After: after, ActiveBefore: "personal", ActiveAfter: "personal"}
	raw, _ := json.Marshal(j)
	must(t, os.WriteFile(e.journalPath(), raw, 0600))
	if e.Recover() == nil {
		t.Fatal("same-name journal with different identities accepted")
	}
	if !bytes.Equal(credentials, c.data) || !bytes.Equal(identity, read(t, e.Paths.IdentityFile)) {
		t.Fatal("invalid relogin journal changed live fields")
	}
}
