// Package accounts switches only the account-owned fields in Claude's live stores.
package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/harveyxiacn/claude-accounts/internal/platform"
)

type snapshot struct {
	OAuth    json.RawMessage `json:"oauth,omitempty"`
	Trusted  json.RawMessage `json:"trustedDeviceToken,omitempty"`
	Identity json.RawMessage `json:"identity,omitempty"`
	SavedAt  time.Time       `json:"savedAt"`
}
type state struct {
	Version  int                 `json:"version"`
	Active   string              `json:"active,omitempty"`
	Accounts map[string]snapshot `json:"accounts"`
}
type journal struct {
	Version      int      `json:"version"`
	Before       snapshot `json:"before"`
	After        snapshot `json:"after"`
	ActiveBefore string   `json:"activeBefore"`
	ActiveAfter  string   `json:"activeAfter,omitempty"`
}
type Entry struct {
	Name, Email string
	Active      bool
}

type Engine struct {
	Paths           platform.Paths
	Credentials     platform.CredentialStore
	CheckIdle       func() error
	WriteFile       func(string, []byte, os.FileMode) error
	RunLogin        func(string) error
	OpenCredentials func(platform.Paths) (platform.CredentialStore, error)
}

func New(p platform.Paths, c platform.CredentialStore) *Engine {
	return &Engine{Paths: p, Credentials: c, CheckIdle: func() error { return platform.CheckIdle(p) }, WriteFile: platform.AtomicWrite, RunLogin: platform.RunLogin, OpenCredentials: platform.OpenCredentials}
}
func (e *Engine) statePath() string   { return filepath.Join(e.Paths.StateDir, "accounts.json") }
func (e *Engine) journalPath() string { return filepath.Join(e.Paths.StateDir, "pending.json") }

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$`)

func checkName(name string) error {
	if !validName.MatchString(name) {
		return errors.New("name must be 1-48 ASCII letters, digits, underscores or hyphens")
	}
	upper := strings.ToUpper(name)
	if upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || (len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '0' && upper[3] <= '9') {
		return errors.New("name is reserved by Windows")
	}
	return nil
}

// Decode without converting numbers to float64. Reject duplicates at every depth
// so rewriting a store cannot silently discard an account or credential sibling.
func object(b []byte) (map[string]json.RawMessage, error) {
	validation := json.NewDecoder(bytes.NewReader(b))
	validation.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := validation.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for validation.More() {
				key, err := validation.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				if seen[k] {
					return errors.New("duplicate JSON key")
				}
				seen[k] = true
				if err = walk(); err != nil {
					return err
				}
			}
		case '[':
			for validation.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = validation.Token()
		return err
	}
	if err := walk(); err != nil {
		return nil, errors.New("invalid or duplicate JSON field")
	}
	if _, err := validation.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, errors.New("invalid JSON object")
		}
		k, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid JSON key")
		}
		if _, ok := m[k]; ok {
			return nil, errors.New("duplicate JSON key")
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, errors.New("invalid JSON value")
		}
		m[k] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, errors.New("unterminated JSON object")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return m, nil
}
func equalJSON(a, b []byte) bool {
	var x, y bytes.Buffer
	if json.Compact(&x, a) != nil || json.Compact(&y, b) != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(x.Bytes(), y.Bytes())
}
func jsonString(m map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(m[k], &s)
	return s
}

func accountField(m map[string]json.RawMessage, key string) json.RawMessage {
	value := m[key]
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil
	}
	return value
}
func (s snapshot) key() (string, error) {
	m, err := object(s.Identity)
	if err != nil {
		return "", errors.New("missing or malformed oauthAccount identity; log in with official Claude Code")
	}
	id, org := jsonString(m, "accountUuid"), jsonString(m, "organizationUuid")
	if id == "" || org == "" {
		return "", errors.New("oauthAccount is missing accountUuid or organizationUuid")
	}
	return id + "\x00" + org, nil
}
func (s snapshot) validate() error {
	m, err := object(s.OAuth)
	if err != nil {
		return errors.New("missing or malformed claudeAiOauth; refusing to replace a saved login")
	}
	if jsonString(m, "accessToken") == "" || jsonString(m, "refreshToken") == "" {
		return errors.New("incomplete OAuth credentials; official subscription login with a refresh token is required")
	}
	var expires int64
	var scopes []string
	if json.Unmarshal(m["expiresAt"], &expires) != nil || expires <= 0 || json.Unmarshal(m["scopes"], &scopes) != nil || len(scopes) == 0 {
		return errors.New("unsupported OAuth metadata; expiresAt and scopes are required")
	}
	if _, err = s.key(); err != nil {
		return err
	}
	return nil
}
func (s snapshot) empty() bool {
	return len(s.OAuth) == 0 && len(s.Identity) == 0 && len(s.Trusted) == 0
}
func safeRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("refusing a non-regular file")
	}
	if info.Size() > 32<<20 {
		return nil, errors.New("JSON store is too large")
	}
	return os.ReadFile(path)
}
func readObject(path string, missingOK bool) (map[string]json.RawMessage, error) {
	b, err := safeRead(path)
	if os.IsNotExist(err) && missingOK {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, errors.New("cannot read JSON store")
	}
	m, err := object(b)
	if err != nil {
		return nil, errors.New("malformed JSON store; original file was not changed")
	}
	return m, nil
}
func (e *Engine) capture() (snapshot, error) {
	b, err := e.Credentials.Read()
	var creds map[string]json.RawMessage
	if os.IsNotExist(err) {
		creds = map[string]json.RawMessage{}
	} else if err != nil {
		return snapshot{}, errors.New("cannot read Claude credential storage")
	} else {
		creds, err = object(b)
		if err != nil {
			return snapshot{}, errors.New("malformed Claude credential storage")
		}
	}
	identity, err := readObject(e.Paths.IdentityFile, true)
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{OAuth: accountField(creds, "claudeAiOauth"), Trusted: accountField(creds, "trustedDeviceToken"), Identity: accountField(identity, "oauthAccount"), SavedAt: time.Now().UTC()}, nil
}
func (e *Engine) loadState() (state, error) {
	s := state{Version: 1, Accounts: map[string]snapshot{}}
	b, err := safeRead(e.statePath())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, errors.New("cannot read saved accounts")
	}
	fields, err := object(b)
	if err != nil {
		return s, errors.New("invalid account vault; refusing to overwrite it")
	}
	if _, ok := fields["version"]; !ok {
		return s, errors.New("unsupported or damaged account vault")
	}
	if _, ok := fields["accounts"]; !ok {
		return s, errors.New("unsupported or damaged account vault")
	}
	for key := range fields {
		if key != "version" && key != "accounts" && key != "active" {
			return s, errors.New("unsupported or damaged account vault")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || s.Version != 1 || s.Accounts == nil {
		return s, errors.New("unsupported or damaged account vault")
	}
	seen := map[string]bool{}
	for name, account := range s.Accounts {
		if checkName(name) != nil || account.validate() != nil {
			return s, errors.New("damaged saved account; original vault was not changed")
		}
		key, _ := account.key()
		if seen[key] {
			return s, errors.New("duplicate account identities in vault")
		}
		seen[key] = true
	}
	return s, nil
}
func (e *Engine) writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.New("cannot encode local state")
	}
	b = append(b, '\n')
	if e.WriteFile(path, b, 0600) != nil {
		return errors.New("cannot write local state; check disk space and permissions")
	}
	return nil
}
func (e *Engine) locked(mutating, allowPending bool, fn func() error) error {
	if err := platform.EnsurePrivateDir(e.Paths.StateDir); err != nil {
		return err
	}
	unlock, err := platform.Lock(filepath.Join(e.Paths.StateDir, "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if !allowPending {
		if _, err := os.Lstat(e.journalPath()); err == nil {
			return errors.New("an interrupted switch needs recovery: close Claude and run claude-accounts recover")
		} else if !os.IsNotExist(err) {
			return errors.New("cannot inspect recovery journal")
		}
	}
	if mutating {
		if err := e.CheckIdle(); err != nil {
			return err
		}
	}
	return fn()
}
func find(s state, live snapshot) string {
	key, err := live.key()
	if err != nil {
		return ""
	}
	for n, a := range s.Accounts {
		k, _ := a.key()
		if key == k {
			return n
		}
	}
	return ""
}
func (e *Engine) Save(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return e.locked(true, false, func() error {
		s, err := e.loadState()
		if err != nil {
			return err
		}
		live, err := e.capture()
		if err != nil {
			return err
		}
		if err = live.validate(); err != nil {
			return err
		}
		existing := find(s, live)
		if existing != "" && existing != name {
			return fmt.Errorf("this account is already saved as %s; use that name", existing)
		}
		if previous, ok := s.Accounts[name]; ok {
			pk, _ := previous.key()
			lk, _ := live.key()
			if pk != lk {
				return errors.New("name belongs to a different account; choose another name")
			}
		}
		s.Accounts[name] = live
		s.Active = name
		return e.writeJSON(e.statePath(), s)
	})
}
func (e *Engine) List() ([]Entry, error) {
	var result []Entry
	err := e.locked(false, false, func() error {
		s, err := e.loadState()
		if err != nil {
			return err
		}
		live, err := e.capture()
		if err != nil {
			return err
		}
		current := ""
		if live.validate() == nil {
			current = find(s, live)
		}
		for name, a := range s.Accounts {
			m, _ := object(a.Identity)
			result = append(result, Entry{Name: name, Email: jsonString(m, "emailAddress"), Active: name == current})
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
		return nil
	})
	return result, err
}
func (e *Engine) Remove(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return e.locked(false, false, func() error {
		s, err := e.loadState()
		if err != nil {
			return err
		}
		if _, ok := s.Accounts[name]; !ok {
			return errors.New("unknown account name")
		}
		delete(s.Accounts, name)
		if s.Active == name {
			s.Active = ""
		}
		return e.writeJSON(e.statePath(), s)
	})
}
func (e *Engine) Use(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return e.locked(true, false, func() error {
		s, err := e.loadState()
		if err != nil {
			return err
		}
		target, ok := s.Accounts[name]
		if !ok {
			return errors.New("unknown account name; save or login first")
		}
		before, err := e.capture()
		if err != nil {
			return err
		}
		if err = before.validate(); err != nil {
			return err
		}
		current := find(s, before)
		if current == "" {
			return errors.New("current live account has not been saved; run claude-accounts save NAME first")
		}
		s.Accounts[current] = before
		s.Active = current
		if err = e.writeJSON(e.statePath(), s); err != nil {
			return err
		}
		if current == name {
			return nil
		}
		return e.transition(s, current, name, before, target)
	})
}
func setField(m map[string]json.RawMessage, k string, v json.RawMessage) {
	if len(v) == 0 {
		delete(m, k)
	} else {
		m[k] = v
	}
}
func (e *Engine) patchCredentials(target snapshot) error {
	b, err := e.Credentials.Read()
	var m map[string]json.RawMessage
	if os.IsNotExist(err) {
		m = map[string]json.RawMessage{}
	} else if err != nil {
		return errors.New("cannot read credentials before update")
	} else {
		m, err = object(b)
		if err != nil {
			return errors.New("malformed credentials before update")
		}
	}
	setField(m, "claudeAiOauth", target.OAuth)
	setField(m, "trustedDeviceToken", target.Trusted)
	b, err = json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errors.New("cannot encode credentials")
	}
	if err = e.Credentials.Write(append(b, '\n')); err != nil {
		return errors.New("cannot update Claude credentials")
	}
	return nil
}
func (e *Engine) patchIdentity(target snapshot) error {
	m, err := readObject(e.Paths.IdentityFile, true)
	if err != nil {
		return err
	}
	setField(m, "oauthAccount", target.Identity)
	return e.writeJSON(e.Paths.IdentityFile, m)
}
func sameAccountFields(a, b snapshot) bool {
	return equalJSON(a.OAuth, b.OAuth) && equalJSON(a.Trusted, b.Trusted) && equalJSON(a.Identity, b.Identity)
}
func (e *Engine) transition(s state, current, name string, before, target snapshot) error {
	// Recheck immediately before durable intent: another process may have changed
	// the live login while we were preparing. The tool lock cannot lock Claude.
	if err := e.CheckIdle(); err != nil {
		return err
	}
	now, err := e.capture()
	if err != nil {
		return err
	}
	if !sameAccountFields(now, before) {
		return errors.New("live account changed during preparation; nothing was switched")
	}
	j := journal{Version: 1, Before: before, After: target, ActiveBefore: current, ActiveAfter: name}
	if err = e.writeJSON(e.journalPath(), j); err != nil {
		return err
	}
	if err = e.patchCredentials(target); err == nil {
		err = e.patchIdentity(target)
	}
	if err == nil {
		s.Accounts[name] = target
		s.Active = name
		err = e.writeJSON(e.statePath(), s)
	}
	if err != nil {
		if rollback := e.rollback(j); rollback != nil {
			return errors.New("switch failed and rollback is incomplete; close Claude and run claude-accounts recover")
		}
		return errors.New("switch failed; previous account restored")
	}
	if err = os.Remove(e.journalPath()); err != nil {
		return errors.New("switch written but recovery journal could not be cleared; run claude-accounts recover before using Claude")
	}
	return nil
}
func allowedField(live, before, after json.RawMessage) bool {
	return equalJSON(live, before) || equalJSON(live, after)
}
func (e *Engine) rollback(j journal) error {
	// Native stores may have two partially committed backends after a crash.
	// Validate identity before asking the adapter to reconcile the journal's
	// known credential generations; never overwrite an external newer login.
	identity, err := readObject(e.Paths.IdentityFile, true)
	if err != nil {
		return err
	}
	if !allowedField(accountField(identity, "oauthAccount"), j.Before.Identity, j.After.Identity) {
		return errors.New("identity changed after interruption; refusing to overwrite newer login")
	}
	if recoverer, ok := e.Credentials.(interface{ RecoverAccount([]byte, []byte) error }); ok {
		pre, post := map[string]json.RawMessage{}, map[string]json.RawMessage{}
		setField(pre, "claudeAiOauth", j.Before.OAuth)
		setField(pre, "trustedDeviceToken", j.Before.Trusted)
		setField(post, "claudeAiOauth", j.After.OAuth)
		setField(post, "trustedDeviceToken", j.After.Trusted)
		before, _ := json.Marshal(pre)
		after, _ := json.Marshal(post)
		if err = recoverer.RecoverAccount(before, after); err != nil {
			return err
		}
	}
	live, err := e.capture()
	if err != nil {
		return err
	}
	if !allowedField(live.OAuth, j.Before.OAuth, j.After.OAuth) || !allowedField(live.Trusted, j.Before.Trusted, j.After.Trusted) || !allowedField(live.Identity, j.Before.Identity, j.After.Identity) {
		return errors.New("account fields changed after interruption; refusing to overwrite newer credentials")
	}
	if err = e.patchCredentials(j.Before); err != nil {
		return err
	}
	if err = e.patchIdentity(j.Before); err != nil {
		return err
	}
	s, err := e.loadState()
	if err != nil {
		return err
	}
	s.Active = j.ActiveBefore
	if err = e.writeJSON(e.statePath(), s); err != nil {
		return err
	}
	return os.Remove(e.journalPath())
}
func (e *Engine) Recover() error {
	return e.locked(true, true, func() error {
		b, err := safeRead(e.journalPath())
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return errors.New("cannot read recovery journal")
		}
		invalid := errors.New("invalid recovery journal; no live data changed")
		fields, err := object(b)
		if err != nil {
			return invalid
		}
		for _, key := range []string{"version", "before", "after", "activeBefore"} {
			if _, ok := fields[key]; !ok {
				return invalid
			}
		}
		for key := range fields {
			if key != "version" && key != "before" && key != "after" && key != "activeBefore" && key != "activeAfter" {
				return invalid
			}
		}
		if _, err := object(fields["before"]); err != nil {
			return invalid
		}
		if _, err := object(fields["after"]); err != nil {
			return invalid
		}
		var j journal
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&j) != nil || j.Version != 1 || (!j.Before.empty() && j.Before.validate() != nil) || j.After.validate() != nil {
			return invalid
		}
		return e.rollback(j)
	})
}

// Login uses only official Claude in a temporary config. Its environment overlay
// is child-local. Thus onboarding cannot reset the real hooks or configuration.
func (e *Engine) Login(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	return e.locked(true, false, func() (result error) {
		s, err := e.loadState()
		if err != nil {
			return err
		}
		before, err := e.capture()
		if err != nil {
			return err
		}
		current := ""
		if !before.empty() {
			if err = before.validate(); err != nil {
				return err
			}
			current = find(s, before)
			if current == "" {
				return errors.New("save the existing login first: claude-accounts save NAME")
			}
			s.Accounts[current] = before
			s.Active = current
			if err = e.writeJSON(e.statePath(), s); err != nil {
				return err
			}
		}
		dir, err := os.MkdirTemp(e.Paths.StateDir, "login-")
		if err != nil {
			return errors.New("cannot create private login directory")
		}
		var temporaryCredentials platform.CredentialStore
		defer func() {
			// Only this generated child can be removed, on success or cancellation.
			if rel, check := filepath.Rel(e.Paths.StateDir, dir); check != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				result = errors.Join(result, errors.New("refusing unsafe temporary cleanup"))
				return
			}
			if temporaryCredentials != nil {
				if cleanup := temporaryCredentials.Delete(); cleanup != nil {
					result = errors.Join(result, fmt.Errorf("temporary credential cleanup failed in %s", dir))
					return
				}
			}
			if cleanup := os.RemoveAll(dir); cleanup != nil {
				result = errors.Join(result, fmt.Errorf("temporary directory cleanup failed in %s", dir))
			}
		}()
		if err = platform.EnsurePrivateDir(dir); err != nil {
			return err
		}
		lookup := func(k string) (string, bool) {
			if k == "CLAUDE_CONFIG_DIR" || k == "CLAUDE_SECURESTORAGE_CONFIG_DIR" {
				return dir, true
			}
			return os.LookupEnv(k)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		p, err := platform.ResolvePaths(home, lookup)
		if err != nil {
			return err
		}
		creds, err := e.OpenCredentials(p)
		if err != nil {
			return err
		}
		temporaryCredentials = creds
		if err = e.RunLogin(dir); err != nil {
			return errors.New("official login did not complete; existing account is unchanged")
		}
		tmp := New(p, creds)
		target, err := tmp.capture()
		if err != nil {
			return err
		}
		if err = target.validate(); err != nil {
			return err
		}
		if existing := find(s, target); existing != "" && existing != name {
			return fmt.Errorf("browser logged into account already saved as %s; main account unchanged", existing)
		}
		if previous, ok := s.Accounts[name]; ok {
			pk, _ := previous.key()
			tk, _ := target.key()
			if pk != tk {
				return errors.New("browser account does not match this saved name; main account unchanged")
			}
		}
		// Save the successfully obtained login durably before touching live state.
		s.Accounts[name] = target
		if err = e.writeJSON(e.statePath(), s); err != nil {
			return err
		}
		if err = e.transition(s, current, name, before, target); err != nil {
			return err
		}
		return nil
	})
}
