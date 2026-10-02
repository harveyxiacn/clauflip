//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPrivateDirectoryRemovesExplicitEveryone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("icacls.exe", path, "/grant", "*S-1-1-0:(OI)(CI)F").Run(); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(path); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$a=Get-Acl -LiteralPath $env:CLAUDE_ACCOUNTS_TEST_DIR; if(-not $a.AreAccessRulesProtected){exit 1}; $rules=@($a.Access); if($rules.Count -ne 1){exit 2}; if($rules[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0'){exit 3}`)
	c.Env = append(os.Environ(), "CLAUDE_ACCOUNTS_TEST_DIR="+path)
	if err := c.Run(); err != nil {
		t.Fatal("directory ACL was not exactly protected user-only", err)
	}
	if err := os.WriteFile(filepath.Join(path, "fixture"), []byte("fixture"), 0600); err != nil {
		t.Fatal("user lost vault access", err)
	}
}
