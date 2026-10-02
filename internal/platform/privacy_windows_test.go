//go:build windows

package platform

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$a=[System.IO.DirectoryInfo]::new($env:CLAUFLIP_TEST_DIR).GetAccessControl(); if(-not $a.AreAccessRulesProtected){exit 1}; $rules=@($a.Access); if($rules.Count -ne 1){exit 2}; if($rules[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0'){exit 3}`)
	c.Env = append(os.Environ(), "CLAUFLIP_TEST_DIR="+path)
	if err := c.Run(); err != nil {
		diagnostic := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershellModulePrelude+`$a=[System.IO.DirectoryInfo]::new($env:CLAUFLIP_TEST_DIR).GetAccessControl(); 'SDDL='+$a.Sddl; 'Protected='+$a.AreAccessRulesProtected; 'ProcessSid='+[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $a.Access | ForEach-Object { 'RuleSid='+$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value+';Inherited='+$_.IsInherited+';Type='+$_.AccessControlType }`)
		diagnostic.Env = append(os.Environ(), "CLAUFLIP_TEST_DIR="+path)
		output, de := diagnostic.CombinedOutput()
		u, _ := user.Current()
		expected := "unavailable"
		if u != nil {
			expected = u.Uid
		}
		t.Fatalf("directory ACL was not exactly protected user-only: %v; fixture expected SID=%s; diagnostic error=%v; %s", err, expected, de, output)
	}
	if err := os.WriteFile(filepath.Join(path, "fixture"), []byte("fixture"), 0600); err != nil {
		t.Fatal("user lost vault access", err)
	}
}

func TestWindowsPowerShellModuleIsolation(t *testing.T) {
	c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershellModulePrelude+`$ErrorActionPreference='Stop'; Import-Module CimCmdlets; Import-Module Microsoft.PowerShell.Security; if(-not (Get-Command Get-CimInstance)){exit 1}`)
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if !strings.EqualFold(key, "PSModulePath") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "PSModulePath="+filepath.Join(t.TempDir(), "fake-pwsh-modules"))
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("Windows PowerShell did not isolate built-in modules: %v: %s", err, b)
	}
}
