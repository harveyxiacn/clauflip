package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/harveyxiacn/clauflip/internal/accounts"
)

type fakeEngine struct {
	called string
	err    error
}

func (f *fakeEngine) Login(n string) error  { f.called = "login " + n; return f.err }
func (f *fakeEngine) Save(n string) error   { f.called = "save " + n; return f.err }
func (f *fakeEngine) Use(n string) error    { f.called = "use " + n; return f.err }
func (f *fakeEngine) Remove(n string) error { f.called = "remove " + n; return f.err }
func (f *fakeEngine) Recover() error        { f.called = "recover"; return f.err }
func (f *fakeEngine) List() ([]accounts.Entry, error) {
	f.called = "list"
	return []accounts.Entry{{Name: "safe\x1b[31m", Email: "a\nb@example.com", Active: true}}, f.err
}

func TestHelpDoesNotOpenStore(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run([]string{"help"}, &out, &stderr, func() (engine, error) { t.Fatal("opened store"); return nil, nil }, func(string) (string, bool) { return "", false })
	if code != 0 || !strings.Contains(out.String(), "save") {
		t.Fatalf("%d %s", code, out.String())
	}
}
func TestInvalidArgumentsDoNotOpenStore(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"use"}, {"list", "extra"}, {"recover", "extra"}} {
		var out, stderr bytes.Buffer
		if run(args, &out, &stderr, func() (engine, error) { t.Fatal("opened store"); return nil, nil }, func(string) (string, bool) { return "", false }) != 2 {
			t.Fatal(args)
		}
	}
}
func TestWarningAndResume(t *testing.T) {
	var out, stderr bytes.Buffer
	f := &fakeEngine{}
	code := run([]string{"use", "personal"}, &out, &stderr, func() (engine, error) { return f, nil }, func(k string) (string, bool) { return "SECRET", k == "ANTHROPIC_API_KEY" })
	if code != 0 || f.called != "use personal" || !strings.Contains(stderr.String(), "ANTHROPIC_API_KEY") || strings.Contains(stderr.String(), "SECRET") || !strings.Contains(out.String(), "claude --continue") {
		t.Fatalf("%d %s %s", code, out.String(), stderr.String())
	}
}
func TestListSanitizesControls(t *testing.T) {
	var out, stderr bytes.Buffer
	run([]string{"list"}, &out, &stderr, func() (engine, error) { return &fakeEngine{}, nil }, func(string) (string, bool) { return "", false })
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "a\nb") {
		t.Fatal(out.String())
	}
}
func TestActionableErrorsSanitizeControls(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run([]string{"save", "x"}, &out, &stderr, func() (engine, error) {
		return &fakeEngine{err: errors.New("\x1bClaude Code is running; close its CLI")}, nil
	}, func(string) (string, bool) { return "", false })
	if code != 1 || strings.Contains(stderr.String(), "\x1b") || !strings.Contains(stderr.String(), "close its CLI") {
		t.Fatalf("%d %s", code, stderr.String())
	}
}

func TestProviderPrefixWarningPreservesEnvironment(t *testing.T) {
	t.Setenv("CLAUDE_CODE_USE_CUSTOM", "SECRET")
	var out, stderr bytes.Buffer
	run([]string{"recover"}, &out, &stderr, func() (engine, error) { return &fakeEngine{}, nil }, os.LookupEnv)
	if !strings.Contains(stderr.String(), "CLAUDE_CODE_USE_CUSTOM") || strings.Contains(stderr.String(), "SECRET") {
		t.Fatal(stderr.String())
	}
	if os.Getenv("CLAUDE_CODE_USE_CUSTOM") != "SECRET" {
		t.Fatal("environment changed")
	}
}
