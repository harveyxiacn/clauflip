//go:build linux || darwin

package platform

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestLoginInterruptPreservesCallerCleanup(t *testing.T) {
	if os.Getenv("CLAUFLIP_INTERRUPT_FIXTURE") == "1" {
		// Deliver the interrupt to the waiting Go caller, then simulate the
		// official login child's cancellation exit. No Claude binary is started.
		if err := syscall.Kill(os.Getppid(), syscall.SIGINT); err != nil {
			os.Exit(2)
		}
		os.Exit(1)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestLoginInterruptPreservesCallerCleanup$")
	c.Env = append(os.Environ(), "CLAUFLIP_INTERRUPT_FIXTURE=1")
	cleanupRan := false
	func() {
		defer func() { cleanupRan = true }()
		if err := runLoginCommand(c); err == nil {
			t.Fatal("cancelled child should return an error")
		}
	}()
	if !cleanupRan {
		t.Fatal("caller cleanup was skipped")
	}
}
