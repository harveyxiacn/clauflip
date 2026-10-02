# claude-accounts

小型跨平台 Claude Code 订阅账户手动切换工具。保存多个已登录身份，切换时保留现有 hooks、设置、项目记录和本地会话。使用 Go，版本 0.1.0。

仅支持官方 Claude Code 订阅 OAuth 登录。账户的访问权限和订阅能力仍由官方服务决定。

## 使用

从工作流产物下载对应平台二进制，或使用 Go 1.26 构建：

```sh
go build -o claude-accounts ./cmd/claude-accounts
```

已有个人账户登录时，先退出 Claude Code，再执行：

```sh
claude-accounts save personal
claude-accounts login work
claude-accounts list
claude-accounts use personal
```

`login work` 在临时私有配置目录中启动官方登录，成功后导入账户字段；临时配置只传给子进程，不修改父进程环境，也不让登录流程改写已有 hooks 和共享配置。

切换后回到原项目目录，重新启动 Claude：

```sh
claude --continue
# 或选择已有会话
claude --resume
```

工具不会自动启动项目会话。切换前应退出正在运行的 Claude Code，避免进程缓存旧身份或并发刷新凭据。

| 命令 | 用途 |
| --- | --- |
| `save NAME` | 保存当前登录身份 |
| `login NAME` | 通过官方登录保存新身份 |
| `list` | 列出本地账户，星号表示当前身份 |
| `use NAME` | 保存当前身份并切换目标账户 |
| `remove NAME` | 删除本地账户快照 |
| `recover` | 恢复未完成切换的本地状态 |
| `help` / `version` | 帮助／版本 |

## 保存范围与限制

只处理 `claudeAiOauth`、`trustedDeviceToken`、`oauthAccount` 账户字段。共享配置与本地会话继续留在原位置。代理、后台刷新、自动轮换、导出和自动更新均不在此工具范围内。

账户快照含敏感登录材料，采用明文存储，与官方 Linux 文件凭据存储类似；这不是加密保险库。POSIX 目录／文件权限为 0700／0600，Windows 使用当前用户 ACL。不要将快照提交到版本库或分享。

环境覆盖变量会保留；修改操作会提示相关变量名称，不打印值。已有 API key、自定义接口或云供应商环境变量可能覆盖所选订阅身份。

提示只检查进程环境变量，不检查 `settings.json` 中的 `env` 或 `apiKeyHelper`。启动后使用 Claude 的 `/status` 确认当前身份与认证方式；这些配置也需手动核对。

快照无法保证刷新令牌永久有效，也无法保证无封号或服务限制。组织策略、账户级连接器授权和权限随身份变化；本地会话保留不代表所有跨身份恢复都一定成功。内部凭据格式不是稳定公开接口。

## 开源参考与验证

研究了高星且持续维护的 CCS、claude-swap 和 CC Switch，但没有候选满足“无已知未解决核心异常”的严格条件，因此未采用上游 fork 或运行时依赖。本项目独立实现，只参考官方 CLI 登录、身份与共享配置分离的设计原则；没有复制上游源码。

具体证据与已知问题见 [开源参考](docs/references.md)。平台自动化与真实账户验证的边界见 [兼容性说明](docs/compatibility.md)。没有执行真实多账户浏览器授权或线上刷新验证。CI 负责三个平台的测试、静态检查及六种目标的二进制构建。

许可证：[MIT](LICENSE)。
