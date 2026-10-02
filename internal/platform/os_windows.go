//go:build windows

package platform

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var lockProc = kernel.NewProc("LockFileEx")
var unlockProc = kernel.NewProc("UnlockFileEx")

func platformUsername() string {
	u, e := user.Current()
	if e != nil {
		return ""
	}
	return u.Username
}
func lockFile(f *os.File) error {
	var ov syscall.Overlapped
	r, _, e := lockProc.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if r == 0 {
		return e
	}
	return nil
}
func unlockFile(f *os.File) {
	var ov syscall.Overlapped
	unlockProc.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
}
func rejectHardlinks(path string, info os.FileInfo) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	var data syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &data); e != nil {
		return e
	}
	if data.NumberOfLinks > 1 {
		return errors.New("refusing multiply linked file")
	}
	return nil
}
func privateDirectory(path string) error {
	u, e := user.Current()
	if e != nil {
		return e
	}
	advapi := syscall.NewLazyDLL("advapi32.dll")
	sddl, e := syscall.UTF16PtrFromString("D:P(A;OICI;FA;;;" + u.Uid + ")")
	if e != nil {
		return e
	}
	var descriptor uintptr
	r, _, err := advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if r == 0 {
		return err
	}
	defer kernel.NewProc("LocalFree").Call(descriptor)
	var present, defaulted uint32
	var dacl uintptr
	r, _, err = advapi.NewProc("GetSecurityDescriptorDacl").Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 || present == 0 {
		return errors.New("cannot construct private directory ACL")
	}
	name, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	r, _, _ = advapi.NewProc("SetNamedSecurityInfoW").Call(uintptr(unsafe.Pointer(name)), 1, 0x80000004, 0, 0, dacl, 0)
	if r != 0 {
		return errors.New("cannot restrict private state directory ACL")
	}
	return nil
}
func syncDirectory(string) error { return nil }
func pidAlive(pid int) (bool, error) {
	h, e := syscall.OpenProcess(0x1000, false, uint32(pid))
	if e != nil {
		if errors.Is(e, syscall.Errno(87)) {
			return false, nil
		}
		return false, e
	}
	syscall.CloseHandle(h)
	return true, nil
}
func scanClaudeProcesses() error {
	// Return only a boolean; command lines and possible embedded secrets never leave this child.
	script := `$ErrorActionPreference='Stop'; $found=Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^claude(\.exe)?$' -or ($_.Name -match '^node(\.exe)?$' -and $_.CommandLine -match '[/\\]@anthropic-ai[/\\]claude-code[/\\].*(cli\.js|cli-wrapper\.cjs)') }; if($found){'active'}else{'idle'}`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if e != nil {
		return errors.New("cannot scan processes; refusing account change")
	}
	if strings.TrimSpace(string(b)) != "idle" {
		return errors.New("Claude Code is running; close its CLI, extension and background sessions before switching")
	}
	return nil
}

func loginCommand() *exec.Cmd {
	// npm installations commonly expose claude.cmd; Windows needs its command interpreter.
	return exec.Command("cmd.exe", "/d", "/c", "claude", "auth", "login", "--claudeai")
}
