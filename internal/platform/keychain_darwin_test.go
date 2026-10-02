//go:build darwin

package platform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt in on a macOS runner with an unlocked test Keychain. Only a fresh,
// tool-owned service is touched; never the actual Claude Code service.
func TestKeychainLargeRoundTrip(t *testing.T) {
	if os.Getenv("CLAUDE_ACCOUNTS_KEYCHAIN_TEST") != "1" && os.Getenv("CI") != "true" {
		t.Skip("requires an unlocked macOS test Keychain")
	}
	dir := t.TempDir()
	s := &keychainStore{p: Paths{CredentialFile: filepath.Join(dir, "absent.json"), KeychainService: fmt.Sprintf("claude-accounts-test-%d", time.Now().UnixNano()), KeychainAccount: platformUsername()}}
	t.Cleanup(func() {
		if err := s.Delete(); err != nil {
			t.Error(err)
		}
	})
	small := []byte(`{"claudeAiOauth":{"accessToken":"first"}}`)
	if err := s.Write(small); err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"claudeAiOauth":{"accessToken":"fixture"},"mcpOAuth":{"fixture":"` + strings.Repeat("x", 15000) + `"}}`)
	if err := s.Write(b); err != nil {
		// This unique test service contains only invented fixture tokens. Preserve
		// native diagnostics here without changing production error redaction.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		output, diagnosticErr := keychainWriteCommandContext(ctx, s.p.KeychainService, s.p.KeychainAccount, b).CombinedOutput()
		t.Fatalf("%v; fixture-only native diagnostic: %v: %s", err, diagnosticErr, output)
	}
	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, b) {
		t.Fatal("large credential round trip differs")
	}
	fallback := []byte(`{"claudeAiOauth":{"accessToken":"fixture"},"mcpOAuth":{"fileOnly":"preserve"}}`)
	if err := os.WriteFile(s.p.CredentialFile, fallback, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err != nil {
		t.Fatal("shared siblings must not create ambiguity", err)
	}
	if err := s.Write(small); err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(s.p.CredentialFile)
	if err != nil || !bytes.Contains(preserved, []byte("fileOnly")) {
		t.Fatal("fallback-only shared state lost", err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := s.Write(b); err == nil {
		t.Fatal("read-only fallback directory should prevent write")
	}
	rolledBack, err := s.keychainRead()
	if err != nil || !bytes.Equal(rolledBack, small) {
		t.Fatal("failed fallback write did not roll back Keychain", err)
	}
	os.Chmod(dir, 0700)
	// Simulate interruption between the Keychain and fallback writes.
	if err := s.writeKeychain(b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("divergent account generations must fail closed")
	}
	before := []byte(`{"claudeAiOauth":{"accessToken":"first"}}`)
	after := []byte(`{"claudeAiOauth":{"accessToken":"fixture"}}`)
	if err := s.RecoverAccount(before, after); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverAccount(before, after); err != nil {
		t.Fatal("recovery should be idempotent", err)
	}
	if _, err := s.Read(); err != nil {
		t.Fatal("recovery failed to reconcile account generations", err)
	}
	preserved, err = os.ReadFile(s.p.CredentialFile)
	if err != nil || !bytes.Contains(preserved, []byte("fileOnly")) {
		t.Fatal("recovery lost fallback shared data", err)
	}
}
