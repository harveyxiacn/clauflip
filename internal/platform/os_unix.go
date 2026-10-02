//go:build linux || darwin

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
)

func platformUsername() string {
	u, e := user.Current()
	if e != nil {
		return ""
	}
	return u.Username
}
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockFile(f *os.File)     { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func rejectHardlinks(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine file link count")
	}
	if st.Nlink > 1 {
		return errors.New("refusing multiply linked file")
	}
	return nil
}
func privateDirectory(path string) error { return os.Chmod(path, 0700) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func pidAlive(pid int) (bool, error) {
	e := syscall.Kill(pid, 0)
	if e == nil || errors.Is(e, syscall.EPERM) {
		return true, nil
	}
	if errors.Is(e, syscall.ESRCH) {
		return false, nil
	}
	return false, e
}
func scanClaudeProcesses() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "ps", "-axo", "comm=,args=").Output()
	if e != nil {
		return errors.New("cannot scan processes; refusing account change")
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		comm := fields[0]
		if comm == "claude" || strings.HasSuffix(comm, "/claude") || (strings.Contains(comm, "node") && strings.Contains(line, "/claude-code/") && (strings.Contains(line, "cli.js") || strings.Contains(line, "cli-wrapper.cjs"))) {
			return errors.New("Claude Code is running; close its CLI, extension and background sessions before switching")
		}
	}
	return nil
}

func loginCommand() *exec.Cmd { return exec.Command("claude", "auth", "login", "--claudeai") }
