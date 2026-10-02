package platform

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPaths(t *testing.T) {
	home := t.TempDir()
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p, err := ResolvePaths(home, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != filepath.Join(home, ".claude") || p.IdentityFile != filepath.Join(home, ".claude.json") || p.KeychainService != "Claude Code-credentials" {
		t.Fatalf("unexpected paths: %+v", p)
	}
	env["CLAUDE_CONFIG_DIR"] = filepath.Join(home, "custom")
	q, err := ResolvePaths(home, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if q.StateDir == p.StateDir || q.IdentityFile != filepath.Join(q.ConfigDir, ".claude.json") || q.KeychainService == p.KeychainService {
		t.Fatal("custom config not isolated")
	}
	if err := os.MkdirAll(q.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(q.ConfigDir, ".config.json")
	if err := os.WriteFile(legacy, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	q, err = ResolvePaths(home, lookup)
	if err != nil || q.IdentityFile != legacy {
		t.Fatal("legacy precedence", err)
	}
	env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = ""
	q, err = ResolvePaths(home, lookup)
	if err != nil || q.KeychainService != "Claude Code-credentials" {
		t.Fatal("empty secure override", err)
	}
}

func TestAtomicAndStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	s := &fileStore{path: path}
	if _, err := s.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := s.Write([]byte(`{"claudeAiOauth":{"accessToken":"fixture"}}`)); err != nil {
		t.Fatal(err)
	}
	b, err := s.Read()
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
	if err := s.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("x"), 0600); err == nil {
		t.Fatal("overwrote directory")
	}
}

func TestLockExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := Lock(path); err == nil {
		u()
		t.Fatal("second lock succeeded")
	}
	unlock()
	u, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	u()
}

func TestRejectLinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	os.WriteFile(target, []byte("safe"), 0600)
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := AtomicWrite(link, []byte("unsafe"), 0600); err == nil {
		t.Fatal("followed link")
	}
}

func TestLargeKeychainWriteUsesStdin(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 10000)
	c := keychainWriteCommand("service", "account", data)
	if c.Path != "/usr/bin/osascript" {
		t.Fatal("large credential must use native Security bridge")
	}
	for _, a := range c.Args {
		if strings.Contains(a, string(data)) {
			t.Fatal("secret in argv")
		}
	}
	got, err := io.ReadAll(c.Stdin)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("stdin payload differs", err)
	}
}

func TestRecoveryAccountPatch(t *testing.T) {
	before := []byte(`{"claudeAiOauth":{"accessToken":"before"}}`)
	after := []byte(`{"claudeAiOauth":{"accessToken":"after"},"trustedDeviceToken":"after-device"}`)
	live := []byte(`{"claudeAiOauth":{"accessToken":"after"},"trustedDeviceToken":"after-device","mcpOAuth":{"secret":"fixture"}}`)
	b, err := recoverAccountPayload(live, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("fixture")) || bytes.Contains(b, []byte("after-device")) || !bytes.Contains(b, []byte("before")) {
		t.Fatal("recovery lost shared data or account fields")
	}
	if _, err := recoverAccountPayload([]byte(`{"claudeAiOauth":{"accessToken":"newer"}}`), before, after); err == nil {
		t.Fatal("accepted unknown credential generation")
	}
}
