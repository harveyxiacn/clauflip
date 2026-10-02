package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/harveyxiacn/clauflip/internal/accounts"
	"github.com/harveyxiacn/clauflip/internal/platform"
)

const version = "0.1.0"
const help = `clauflip 0.1.0 — Claude Code 订阅账户手动切换

用法：clauflip COMMAND [NAME]
  login NAME  使用官方登录并保存新账户
  save NAME   保存当前已登录账户
  list        显示已保存账户
  use NAME    保存当前身份并切换到指定账户
  remove NAME 删除本地账户快照
  recover     恢复未完成切换的本地状态
  help        显示帮助
  version     显示版本

切换前退出 Claude Code。切换后回到原项目，运行 claude --continue 或 claude --resume。
`

type engine interface {
	Login(string) error
	Save(string) error
	Use(string) error
	Remove(string) error
	Recover() error
	List() ([]accounts.Entry, error)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, openEngine, os.LookupEnv)) }

func openEngine() (engine, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	paths, err := platform.ResolvePaths(home, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	creds, err := platform.OpenCredentials(paths)
	if err != nil {
		return nil, err
	}
	return accounts.New(paths, creds), nil
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

func run(args []string, out, stderr io.Writer, open func() (engine, error), lookup func(string) (string, bool)) int {
	if len(args) == 0 {
		fmt.Fprint(out, help)
		return 0
	}
	command := args[0]
	arity := 1
	switch command {
	case "login", "save", "use", "remove":
		arity = 2
	case "help", "--help", "-h", "version", "--version", "list", "recover":
	default:
		fmt.Fprintln(stderr, "未知命令；运行 clauflip help。")
		return 2
	}
	if len(args) != arity || (arity == 2 && strings.TrimSpace(args[1]) == "") {
		fmt.Fprintln(stderr, "参数错误；运行 clauflip help。")
		return 2
	}
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Fprint(out, help)
		return 0
	}
	if command == "version" || command == "--version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if command != "list" {
		warnEnvironment(stderr, lookup)
	}
	e, err := open()
	if err != nil {
		fmt.Fprintf(stderr, "无法打开账户存储：%s\n", clean(err.Error()))
		return 1
	}
	switch command {
	case "list":
		var entries []accounts.Entry
		entries, err = e.List()
		if err == nil {
			for _, entry := range entries {
				mark := " "
				if entry.Active {
					mark = "*"
				}
				fmt.Fprintf(out, "%s %s\t%s\n", mark, clean(entry.Name), clean(entry.Email))
			}
		}
	case "login":
		err = e.Login(args[1])
	case "save":
		err = e.Save(args[1])
	case "use":
		err = e.Use(args[1])
	case "remove":
		err = e.Remove(args[1])
	case "recover":
		err = e.Recover()
	}
	if err != nil {
		fmt.Fprintf(stderr, "操作失败：%s\n", clean(err.Error()))
		return 1
	}
	if command == "use" || command == "login" {
		fmt.Fprintln(out, "账户已就绪。回到原项目目录，运行 claude --continue 或 claude --resume。")
	} else if command != "list" {
		fmt.Fprintln(out, "操作完成。")
	}
	return 0
}

func warnEnvironment(w io.Writer, lookup func(string) (string, bool)) {
	keys := []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "ANTHROPIC_PROFILE", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "CLAUDE_CODE_USE_") {
			found := false
			for _, existing := range keys {
				if existing == key {
					found = true
					break
				}
			}
			if !found {
				keys = append(keys, key)
			}
		}
	}
	var present []string
	for _, key := range keys {
		if _, ok := lookup(key); ok {
			present = append(present, key)
		}
	}
	if len(present) > 0 {
		fmt.Fprintf(w, "警告：环境覆盖可能影响订阅账户选择，已保留：%s\n", clean(strings.Join(present, ", ")))
	}
}
