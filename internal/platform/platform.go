package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"
)

type Paths struct {
	ConfigDir, IdentityFile, CredentialFile, StateDir string
	KeychainService, KeychainAccount                  string
}
type CredentialStore interface {
	Read() ([]byte, error)
	Write([]byte) error
	Delete() error
}

func ResolvePaths(home string, lookup func(string) (string, bool)) (Paths, error) {
	if home == "" {
		return Paths{}, errors.New("home directory is missing")
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return Paths{}, err
	}
	raw, _ := lookup("CLAUDE_CONFIG_DIR")
	config := raw
	if config == "" {
		config = filepath.Join(home, ".claude")
	}
	config, err = filepath.Abs(config)
	if err != nil {
		return Paths{}, err
	}
	identity := filepath.Join(home, ".claude.json")
	if raw != "" {
		identity = filepath.Join(config, ".claude.json")
	}
	legacy := filepath.Join(config, ".config.json")
	if _, err := os.Lstat(legacy); err == nil {
		identity = legacy
	} else if !errors.Is(err, os.ErrNotExist) {
		return Paths{}, err
	}
	secure, defined := lookup("CLAUDE_SECURESTORAGE_CONFIG_DIR")
	if !defined {
		secure = raw
	}
	service := "Claude Code-credentials"
	if secure != "" {
		sum := sha256.Sum256([]byte(norm.NFC.String(secure)))
		service += "-" + hex.EncodeToString(sum[:])[:8]
	}
	account, _ := lookup("USER")
	if account == "" {
		account = platformUsername()
	}
	if account == "" {
		account = "claude-code-user"
	}
	backendBinding := config + "\x00" + identity
	if runtime.GOOS == "darwin" {
		backendBinding += "\x00" + service + "\x00" + account
	}
	binding := sha256.Sum256([]byte(backendBinding))
	return Paths{config, identity, filepath.Join(config, ".credentials.json"), filepath.Join(home, ".claude-accounts", hex.EncodeToString(binding[:])[:16]), service, account}, nil
}

func checkPath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				trustedAlias := false
				if runtime.GOOS == "darwin" && (current == "/var" || current == "/tmp") {
					target, e := os.Readlink(current)
					if e == nil {
						if !filepath.IsAbs(target) {
							target = filepath.Join(filepath.Dir(current), target)
						}
						trustedAlias = filepath.Clean(target) == "/private"+current
					}
				}
				if !trustedAlias {
					return fmt.Errorf("refusing symbolic link: %s", current)
				}
			}
			if current == absolute && info.Mode().IsRegular() {
				if err := rejectHardlinks(current, info); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func EnsurePrivateDir(path string) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return privateDirectory(path)
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := checkPath(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("target is not a regular file")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".claude-accounts-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = checkPath(path); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

type fileStore struct{ path string }

func (s *fileStore) Read() ([]byte, error) {
	if err := checkPath(s.path); err != nil {
		return nil, err
	}
	return os.ReadFile(s.path)
}
func (s *fileStore) Write(b []byte) error {
	if err := checkPath(filepath.Dir(s.path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	return AtomicWrite(s.path, b, 0600)
}
func (s *fileStore) Delete() error {
	if err := checkPath(s.path); err != nil {
		return err
	}
	err := os.Remove(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func OpenCredentials(p Paths) (CredentialStore, error) {
	if err := checkPath(p.CredentialFile); err != nil {
		return nil, err
	}
	if runtime.GOOS == "darwin" {
		return &keychainStore{p: p}, nil
	}
	return &fileStore{p.CredentialFile}, nil
}

type keychainStore struct{ p Paths }

func (s *keychainStore) keychainRead() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-a", s.p.KeychainAccount, "-s", s.p.KeychainService, "-w")
	var out bytes.Buffer
	c.Stdout = &out
	if err := c.Run(); err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) && e.ExitCode() == 44 {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("macOS Keychain credential read failed; unlock the Keychain and retry")
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}
func accountFields(b []byte) ([]byte, error) {
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("malformed credential JSON")
	}
	if d == nil {
		return nil, errors.New("credential must be JSON object")
	}
	return json.Marshal(map[string]any{"claudeAiOauth": d["claudeAiOauth"], "trustedDeviceToken": d["trustedDeviceToken"]})
}
func (s *keychainStore) Read() ([]byte, error) {
	key, ke := s.keychainRead()
	file, fe := (&fileStore{s.p.CredentialFile}).Read()
	if ke != nil && !errors.Is(ke, os.ErrNotExist) {
		return nil, ke
	}
	if fe != nil && !errors.Is(fe, os.ErrNotExist) {
		return nil, fe
	}
	if ke == nil && fe == nil {
		a, err := accountFields(key)
		if err != nil {
			return nil, err
		}
		b, err := accountFields(file)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(a, b) {
			return nil, errors.New("Keychain and file account credentials differ; resolve the stale fallback before switching")
		}
	}
	if ke == nil {
		return key, nil
	}
	return file, fe
}
func securityQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

// The native Security bridge handles large MCP/plugin credential objects without
// the security CLI's fixed interactive input buffer. Credential bytes enter only
// through stdin. Service/account arguments contain no tokens.
const keychainWriteScript = `ObjC.import('Foundation'); ObjC.import('Security');
function run(argv) {
 var query = $.NSMutableDictionary.alloc.init;
 query.setObjectForKey(ObjC.castRefToObject($.kSecClassGenericPassword), ObjC.castRefToObject($.kSecClass));
 query.setObjectForKey($(argv[0]), ObjC.castRefToObject($.kSecAttrService));
 query.setObjectForKey($(argv[1]), ObjC.castRefToObject($.kSecAttrAccount));
 var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
 query.setObjectForKey($.NSNumber.numberWithBool(true), ObjC.castRefToObject($.kSecReturnRef));
 query.setObjectForKey(ObjC.castRefToObject($.kSecMatchLimitOne), ObjC.castRefToObject($.kSecMatchLimit));
 var item = Ref();
 var status = Number($.SecItemCopyMatching(query, item));
 if (status !== 0) throw new Error('Existing Keychain item lookup failed (' + status + ')');
 // Match security -U's legacy content-only update. SecItemUpdate may recreate
 // access policy under this host; changing the item's ACL is not authorized.
 status = Number($.SecKeychainItemModifyContent(item[0], null, Number(data.length), data.bytes));
 if (status !== 0) throw new Error('Keychain write failed (' + status + ')');
}`

func keychainWriteCommand(service, account string, b []byte) *exec.Cmd {
	return keychainWriteCommandContext(context.Background(), service, account, b)
}
func keychainWriteCommandContext(ctx context.Context, service, account string, b []byte) *exec.Cmd {
	line := "add-generic-password -U -a " + securityQuote(account) + " -s " + securityQuote(service) + " -X " + hex.EncodeToString(b) + "\n"
	if len(line) <= 4032 {
		c := exec.CommandContext(ctx, "/usr/bin/security", "-i")
		c.Stdin = strings.NewReader(line)
		return c
	}
	c := exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e", keychainWriteScript, service, account)
	c.Stdin = bytes.NewReader(b)
	return c
}
func (s *keychainStore) Write(b []byte) error {
	if _, err := s.Read(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	previous, previousErr := s.keychainRead()
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return previousErr
	}
	fallback, fallbackErr := (&fileStore{s.p.CredentialFile}).Read()
	if fallbackErr != nil && !errors.Is(fallbackErr, os.ErrNotExist) {
		return fallbackErr
	}
	var updatedFallback []byte
	if fallbackErr == nil {
		var target, old map[string]json.RawMessage
		if json.Unmarshal(b, &target) != nil || json.Unmarshal(fallback, &old) != nil || old == nil || target == nil {
			return errors.New("malformed credential object")
		}
		for _, key := range []string{"claudeAiOauth", "trustedDeviceToken"} {
			if v, ok := target[key]; ok {
				old[key] = v
			} else {
				delete(old, key)
			}
		}
		var err error
		updatedFallback, err = json.Marshal(old)
		if err != nil {
			return err
		}
	}
	// Keep the backend Claude already selected. A file fallback often means
	// Keychain is unavailable (for example SSH); switching must not migrate it.
	if errors.Is(previousErr, os.ErrNotExist) && fallbackErr == nil {
		return (&fileStore{s.p.CredentialFile}).Write(updatedFallback)
	}
	if err := s.writeKeychain(b); err != nil {
		return err
	}
	if fallbackErr == nil {
		if err := (&fileStore{s.p.CredentialFile}).Write(updatedFallback); err != nil {
			var rollbackErr error
			if previousErr == nil {
				rollbackErr = s.writeKeychain(previous)
			} else {
				rollbackErr = s.deleteKeychain()
			}
			if rollbackErr != nil {
				return errors.New("fallback write and Keychain rollback failed; recovery is required")
			}
			return errors.New("fallback write failed; previous Keychain credential restored")
		}
	}
	return nil
}

func (s *keychainStore) writeKeychain(b []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := keychainWriteCommandContext(ctx, s.p.KeychainService, s.p.KeychainAccount, b)
	if err := c.Run(); err != nil {
		return errors.New("macOS Keychain credential write failed")
	}
	got, err := s.keychainRead()
	if err != nil {
		return err
	}
	if !bytes.Equal(got, b) {
		return errors.New("macOS Keychain write verification failed")
	}
	return nil
}
func (s *keychainStore) Delete() error {
	if err := s.deleteKeychain(); err != nil {
		return err
	}
	return (&fileStore{s.p.CredentialFile}).Delete()
}
func (s *keychainStore) deleteKeychain() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-a", s.p.KeychainAccount, "-s", s.p.KeychainService)
	if err := c.Run(); err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ExitCode() != 44 {
			return errors.New("macOS Keychain credential delete failed")
		}
	}
	return nil
}

func recoverAccountPayload(live, before, after []byte) ([]byte, error) {
	if len(before) == 0 {
		before = []byte("{}")
	}
	if len(after) == 0 {
		after = []byte("{}")
	}
	current, err := accountFields(live)
	if err != nil {
		return nil, err
	}
	pre, err := accountFields(before)
	if err != nil {
		return nil, err
	}
	post, err := accountFields(after)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(current, pre) && !bytes.Equal(current, post) {
		return nil, errors.New("live credential generation differs from the recovery journal")
	}
	var original, target map[string]json.RawMessage
	if json.Unmarshal(live, &original) != nil || json.Unmarshal(before, &target) != nil {
		return nil, errors.New("invalid recovery credential object")
	}
	for _, key := range []string{"claudeAiOauth", "trustedDeviceToken"} {
		if v, ok := target[key]; ok {
			original[key] = v
		} else {
			delete(original, key)
		}
	}
	return json.Marshal(original)
}

// RecoverAccount resolves only generations explicitly recorded in the caller's
// durable journal. Each backend retains its own unrelated integration fields.
func (s *keychainStore) RecoverAccount(before, after []byte) error {
	key, ke := s.keychainRead()
	file, fe := (&fileStore{s.p.CredentialFile}).Read()
	if ke != nil && !errors.Is(ke, os.ErrNotExist) {
		return ke
	}
	if fe != nil && !errors.Is(fe, os.ErrNotExist) {
		return fe
	}
	var restoredKey, restoredFile []byte
	var err error
	if ke == nil {
		restoredKey, err = recoverAccountPayload(key, before, after)
		if err != nil {
			return err
		}
	}
	if fe == nil {
		restoredFile, err = recoverAccountPayload(file, before, after)
		if err != nil {
			return err
		}
	}
	if ke != nil && fe != nil {
		if len(before) == 0 {
			return nil
		}
		fields, err := accountFields(before)
		if err != nil {
			return err
		}
		empty, _ := accountFields([]byte("{}"))
		if bytes.Equal(fields, empty) {
			return nil
		}
		return errors.New("all live credential stores are missing; recovery requires inspection")
	}
	if ke == nil {
		if err = s.writeKeychain(restoredKey); err != nil {
			return err
		}
	}
	if fe == nil {
		if err = (&fileStore{s.p.CredentialFile}).Write(restoredFile); err != nil {
			return err
		}
	}
	return nil
}

func Lock(path string) (func(), error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(f); err != nil {
		f.Close()
		return nil, errors.New("another claude-accounts command is running")
	}
	var once sync.Once
	return func() { once.Do(func() { unlockFile(f); f.Close() }) }, nil
}

func RunLogin(configDir string) error {
	c := loginCommand()
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if !strings.EqualFold(key, "CLAUDE_CONFIG_DIR") && !strings.EqualFold(key, "CLAUDE_SECURESTORAGE_CONFIG_DIR") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "CLAUDE_CONFIG_DIR="+configDir, "CLAUDE_SECURESTORAGE_CONFIG_DIR="+configDir)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return runLoginCommand(c)
}

func runLoginCommand(c *exec.Cmd) error {
	// The attached child receives console Ctrl-C too. Keep the waiting parent
	// alive until it returns so the caller can clean its temporary login state.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	return c.Run()
}

func CheckIdle(p Paths) error {
	entries, err := os.ReadDir(filepath.Join(p.ConfigDir, "sessions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect Claude sessions")
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.ConfigDir, "sessions", e.Name()))
		if err != nil {
			return errors.New("cannot inspect Claude session record")
		}
		var d struct {
			PID int `json:"pid"`
		}
		if json.Unmarshal(b, &d) != nil || d.PID <= 0 {
			return errors.New("invalid Claude session record; close Claude and resolve it before switching")
		}
		alive, err := pidAlive(d.PID)
		if err != nil {
			return errors.New("cannot verify Claude process state")
		}
		if alive {
			return errors.New("Claude Code is running; close its CLI, extension and background sessions before switching")
		}
	}
	return scanClaudeProcesses()
}
