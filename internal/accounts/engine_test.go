package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harveyxiacn/clauflip/internal/platform"
)

type memoryCredentials struct {
	data []byte
	fail bool
}

func (m *memoryCredentials) Read() ([]byte, error) {
	if m.data == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(m.data), nil
}
func (m *memoryCredentials) Write(b []byte) error {
	if m.fail {
		return errors.New("injected write failure")
	}
	m.data = bytes.Clone(b)
	return nil
}
func (m *memoryCredentials) Delete() error { m.data = nil; return nil }

func fixture(t *testing.T) (*Engine, *memoryCredentials) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	os.MkdirAll(dir, 0700)
	p := platform.Paths{ConfigDir: dir, IdentityFile: filepath.Join(home, ".claude.json"), CredentialFile: filepath.Join(dir, ".credentials.json"), StateDir: filepath.Join(home, "vault")}
	c := &memoryCredentials{}
	e := New(p, c)
	e.CheckIdle = func() error { return nil }
	setLive(t, e, c, "a", "a-old", true)
	return e, c
}
func setLive(t *testing.T, e *Engine, c *memoryCredentials, id, token string, trusted bool) {
	t.Helper()
	creds := map[string]any{"claudeAiOauth": map[string]any{"accessToken": token, "refreshToken": "refresh-" + token, "expiresAt": 2000000000000, "scopes": []string{"user:inference"}}, "mcpOAuth": map[string]any{"keep": "mcp-secret"}, "pluginSecrets": map[string]any{"keep": "plugin-secret"}}
	if trusted {
		creds["trustedDeviceToken"] = "device-" + id
	}
	c.data, _ = json.Marshal(creds)
	identity := map[string]any{"oauthAccount": map[string]any{"accountUuid": id, "organizationUuid": "org-" + id, "emailAddress": id + "@example.test"}, "projects": map[string]any{"x": map[string]any{"allowedTools": []string{"Read"}}}, "largeInteger": json.Number("9007199254740993"), "theme": "dark"}
	b, _ := json.Marshal(identity)
	if err := os.WriteFile(e.Paths.IdentityFile, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func rawMap(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSwitchPreservesConfigurationAndCapturesRefresh(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	setLive(t, e, c, "b", "b-old", false)
	must(t, e.Save("work"))
	settings := filepath.Join(e.Paths.ConfigDir, "settings.json")
	history := filepath.Join(e.Paths.ConfigDir, "history.jsonl")
	must(t, os.WriteFile(settings, []byte(`{"hooks":{"SessionStart":["unchanged"]},"env":{"EXAMPLE":"value"}}`), 0600))
	must(t, os.WriteFile(history, []byte("conversation-bytes\n"), 0600))
	settingsBefore := read(t, settings)
	historyBefore := read(t, history)
	identityBefore := rawMap(t, read(t, e.Paths.IdentityFile))
	credBefore := rawMap(t, c.data)
	setLive(t, e, c, "b", "b-refreshed", false)
	must(t, e.Use("personal"))
	if !bytes.Contains(c.data, []byte("a-old")) {
		t.Fatal("wrong account")
	}
	if !bytes.Equal(settingsBefore, read(t, settings)) || !bytes.Equal(historyBefore, read(t, history)) {
		t.Fatal("unrelated file changed")
	}
	after := rawMap(t, read(t, e.Paths.IdentityFile))
	for _, k := range []string{"projects", "largeInteger", "theme"} {
		if !equalJSON(identityBefore[k], after[k]) {
			t.Fatalf("identity sibling %s changed", k)
		}
	}
	creds := rawMap(t, c.data)
	for _, k := range []string{"mcpOAuth", "pluginSecrets"} {
		if !equalJSON(credBefore[k], creds[k]) {
			t.Fatalf("credential sibling %s changed", k)
		}
	}
	must(t, e.Use("work"))
	if !bytes.Contains(c.data, []byte("b-refreshed")) {
		t.Fatal("lost refreshed outgoing token")
	}
	if _, ok := rawMap(t, c.data)["trustedDeviceToken"]; ok {
		t.Fatal("previous account device token leaked")
	}
}
func TestMissingLiveOAuthDoesNotDestroySavedAccount(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before := read(t, e.statePath())
	c.data = []byte(`{"mcpOAuth":{"keep":true}}`)
	if err := e.Save("personal"); err == nil {
		t.Fatal("missing oauth accepted")
	}
	if !bytes.Equal(before, read(t, e.statePath())) {
		t.Fatal("saved login overwritten")
	}
	if err := e.Use("personal"); err == nil {
		t.Fatal("ambiguous missing live oauth accepted")
	}
}
func TestUnknownLiveAccountMustBeSavedBeforeSwitch(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	setLive(t, e, c, "b", "b", false)
	before := bytes.Clone(c.data)
	if e.Use("personal") == nil {
		t.Fatal("untracked account would be lost")
	}
	if !bytes.Equal(before, c.data) {
		t.Fatal("changed credentials")
	}
}
func TestRejectDuplicateIdentityAndNameReplacement(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	if e.Save("alias") == nil {
		t.Fatal("duplicate refresh token identity accepted")
	}
	setLive(t, e, c, "b", "b", false)
	if e.Save("personal") == nil {
		t.Fatal("replaced account under existing name")
	}
}
func TestSwitchRollsBackFailedIdentityWrite(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	setLive(t, e, c, "b", "b", false)
	must(t, e.Save("work"))
	before := bytes.Clone(c.data)
	original := e.WriteFile
	count := 0
	e.WriteFile = func(path string, b []byte, mode os.FileMode) error {
		if path == e.Paths.IdentityFile {
			count++
			if count == 1 {
				return errors.New("disk full")
			}
		}
		return original(path, b, mode)
	}
	if err := e.Use("personal"); err == nil {
		t.Fatal("expected failure")
	}
	if !equalJSON(before, c.data) {
		t.Fatal("credentials not rolled back")
	}
	if _, err := os.Stat(e.journalPath()); !os.IsNotExist(err) {
		t.Fatal("completed rollback left pending journal")
	}
}
func TestRecoverPreservesUnrelatedChanges(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	setLive(t, e, c, "b", "b", false)
	must(t, e.Save("work"))
	before, _ := e.capture()
	state, _ := e.loadState()
	target := state.Accounts["personal"]
	must(t, e.writeJSON(e.journalPath(), journal{Version: 1, Before: before, After: target, ActiveBefore: "work"}))
	must(t, e.patchCredentials(target))
	m := rawMap(t, c.data)
	m["newPlugin"] = json.RawMessage(`{"keep":true}`)
	c.data, _ = json.Marshal(m)
	if e.Use("personal") == nil {
		t.Fatal("pending journal not blocked")
	}
	must(t, e.Recover())
	oauth := rawMap(t, rawMap(t, c.data)["claudeAiOauth"])
	if jsonString(oauth, "accessToken") != "b" {
		t.Fatal("did not restore outgoing credentials")
	}
	if _, ok := rawMap(t, c.data)["newPlugin"]; !ok {
		t.Fatal("recovery destroyed unrelated update")
	}
}
func TestMalformedInputAndInvalidNamesNeverWrite(t *testing.T) {
	for _, name := range []string{"../escape", "", "a/b", "a\\b", "CON", "x\nsecret"} {
		t.Run(name, func(t *testing.T) {
			e, _ := fixture(t)
			if e.Save(name) == nil {
				t.Fatal("invalid name accepted")
			}
		})
	}
	e, c := fixture(t)
	must(t, e.Save("personal"))
	c.data = []byte(`{"claudeAiOauth":`)
	if e.Use("personal") == nil {
		t.Fatal("malformed live store accepted")
	}
	c.data = []byte(`{"claudeAiOauth":{"accessToken":"secret-print-me","refreshToken":"r"}}`)
	err := e.Save("personal")
	if err != nil && strings.Contains(err.Error(), "secret-print-me") {
		t.Fatal("secret leaked in error")
	}
}
func TestActiveProcessGuardBlocksMutations(t *testing.T) {
	e, c := fixture(t)
	before := bytes.Clone(c.data)
	e.CheckIdle = func() error { return errors.New("Claude still running") }
	if e.Save("personal") == nil {
		t.Fatal("active process ignored")
	}
	if !bytes.Equal(before, c.data) {
		t.Fatal("credentials changed")
	}
}
func TestRemoveOnlyForgetsSavedLogin(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before := bytes.Clone(c.data)
	must(t, e.Remove("personal"))
	if !bytes.Equal(before, c.data) {
		t.Fatal("remove logged out live account")
	}
	entries, err := e.List()
	must(t, err)
	if len(entries) != 0 {
		t.Fatal("entry remains")
	}
}

func fakeLogin(t *testing.T, e *Engine, id string, fail bool) {
	t.Helper()
	stores := map[string]*memoryCredentials{}
	e.OpenCredentials = func(p platform.Paths) (platform.CredentialStore, error) {
		c := &memoryCredentials{}
		stores[p.ConfigDir] = c
		return c, nil
	}
	e.RunLogin = func(dir string) error {
		if fail {
			return errors.New("login cancelled token-must-not-leak")
		}
		if dir == e.Paths.ConfigDir {
			t.Fatal("login touched main config")
		}
		p := platform.Paths{ConfigDir: dir, IdentityFile: filepath.Join(dir, ".claude.json")}
		tmp := New(p, stores[dir])
		setLive(t, tmp, stores[dir], id, "new-login-"+id, false)
		return nil
	}
}
func TestLoginImportsOnlyAccountFieldsAndRetainsCurrent(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	original := rawMap(t, read(t, e.Paths.IdentityFile))
	fakeLogin(t, e, "b", false)
	must(t, e.Login("work"))
	if !bytes.Contains(c.data, []byte("new-login-b")) {
		t.Fatal("login not activated")
	}
	after := rawMap(t, read(t, e.Paths.IdentityFile))
	for _, k := range []string{"projects", "largeInteger", "theme"} {
		if !equalJSON(original[k], after[k]) {
			t.Fatalf("changed %s", k)
		}
	}
	must(t, e.Use("personal"))
	if !bytes.Contains(c.data, []byte("a-old")) {
		t.Fatal("old account lost")
	}
	entries, err := os.ReadDir(e.Paths.StateDir)
	must(t, err)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "login-") {
			t.Fatal("temporary credentials not removed")
		}
	}
}
func TestCancelledLoginDoesNotAlterLiveAccount(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before := bytes.Clone(c.data)
	identity := read(t, e.Paths.IdentityFile)
	fakeLogin(t, e, "b", true)
	err := e.Login("work")
	if err == nil || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatal("login error missing or leaks")
	}
	if !bytes.Equal(before, c.data) || !bytes.Equal(identity, read(t, e.Paths.IdentityFile)) {
		t.Fatal("cancelled login changed live state")
	}
}
func TestFirstLoginWithoutExistingCredentials(t *testing.T) {
	e, c := fixture(t)
	c.data = nil
	must(t, os.Remove(e.Paths.IdentityFile))
	fakeLogin(t, e, "a", false)
	must(t, e.Login("personal"))
	entries, err := e.List()
	must(t, err)
	if len(entries) != 1 || !entries[0].Active {
		t.Fatal("first account not activated")
	}
}

func TestLoginTreatsNullAccountFieldsAsSignedOut(t *testing.T) {
	e, c := fixture(t)
	c.data = []byte(`{"claudeAiOauth":null,"trustedDeviceToken":null,"mcpOAuth":{"keep":true}}`)
	must(t, os.WriteFile(e.Paths.IdentityFile, []byte(`{"oauthAccount":null,"theme":"dark"}`), 0600))
	fakeLogin(t, e, "a", false)
	must(t, e.Login("personal"))
	if _, ok := rawMap(t, c.data)["mcpOAuth"]; !ok {
		t.Fatal("lost shared MCP credentials")
	}
}
func TestCorruptJournalCannotOverwriteNewLiveCredentials(t *testing.T) {
	e, c := fixture(t)
	must(t, e.Save("personal"))
	before, _ := e.capture()
	setLive(t, e, c, "b", "b", false)
	must(t, e.Save("work"))
	target, _ := e.capture()
	must(t, e.writeJSON(e.journalPath(), journal{Version: 1, Before: before, After: target}))
	setLive(t, e, c, "b", "fresh-outside-tool", false)
	fresh := bytes.Clone(c.data)
	if e.Recover() == nil {
		t.Fatal("overwrote externally refreshed credentials")
	}
	if !bytes.Equal(fresh, c.data) {
		t.Fatal("fresh credential changed")
	}
}
func TestMalformedCredentialMetadataRejected(t *testing.T) {
	for _, value := range []string{`{"accessToken":"a","refreshToken":"r"}`, `{"accessToken":"a","refreshToken":"r","expiresAt":0,"scopes":["user:inference"]}`, `{"accessToken":"a","refreshToken":"r","expiresAt":2000000000000,"scopes":"bad"}`} {
		t.Run(value, func(t *testing.T) {
			e, c := fixture(t)
			m := rawMap(t, c.data)
			m["claudeAiOauth"] = json.RawMessage(value)
			c.data, _ = json.Marshal(m)
			if e.Save("personal") == nil {
				t.Fatal("malformed token metadata accepted")
			}
		})
	}
}

func TestFailedLoginCleansTemporaryCredentials(t *testing.T) {
	for _, cancel := range []bool{true, false} {
		t.Run(fmt.Sprint(cancel), func(t *testing.T) {
			e, _ := fixture(t)
			must(t, e.Save("personal"))
			fakeLogin(t, e, "a", cancel)
			if e.Login("work") == nil {
				t.Fatal("expected cancelled or duplicate browser login")
			}
			entries, err := os.ReadDir(e.Paths.StateDir)
			must(t, err)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "login-") {
					t.Fatal("failed login left credential directory behind")
				}
			}
		})
	}
}
