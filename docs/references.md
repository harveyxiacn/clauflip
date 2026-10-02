# 开源参考与取舍

核查日期：2026-10-02。以下数据来自 GitHub 公共仓库 API、主分支源码、发布记录和问题记录；星数、维护状态和问题状态会变化。

| 项目 | 星数 | 许可证 | 主分支最近提交 | 最近正式发布 |
| --- | ---: | --- | --- | --- |
| [claude-swap](https://github.com/realiti4/claude-swap) | 2,986 | MIT | 2026-09-28 | [v0.26.0](https://github.com/realiti4/claude-swap/releases/tag/v0.26.0)，2026-09-02 |
| [CCS](https://github.com/kaitranntt/ccs) | 2,868 | MIT | 2026-09-11 | [v8.10.0](https://github.com/kaitranntt/ccs/releases/tag/v8.10.0)，2026-09-11 |
| [CC Switch](https://github.com/farion1231/cc-switch) | 139,406 | MIT | 2026-10-02 | [v3.20.4](https://github.com/farion1231/cc-switch/releases/tag/v3.20.4)，2026-09-22 |

仓库元数据可分别从 [claude-swap API](https://api.github.com/repos/realiti4/claude-swap)、[CCS API](https://api.github.com/repos/kaitranntt/ccs)、[CC Switch API](https://api.github.com/repos/farion1231/cc-switch) 复核。CCS 最近主分支提交与最近仓库推送不同：后者为 2026-10-01。

## 严格筛选结论

没有候选通过“高星、持续维护、没有已知未解决核心异常”的全部条件，因此本项目没有直接采用它们的 fork 或运行时依赖。公开问题搜索也无法证明不存在封号、凭据失效或未公开故障。

本项目独立实现。参考的是设计原则，没有复制上游源码；当前无需附带上游 MIT 许可证文本。将来如果复制源码，应保留相应版权和许可证声明。

## 有选择地参考

[CCS 原生账户实例管理](https://github.com/kaitranntt/ccs/blob/main/src/management/instance-manager.ts) 将直接登录与第三方 OAuth 代理区分开：每个实例使用自己的 `CLAUDE_CONFIG_DIR`，让 Claude CLI 管理凭据，而不是由 CCS 复制或刷新。其 [共享资源策略](https://github.com/kaitranntt/ccs/blob/main/src/auth/shared-resource-policy.ts) 和 [账户上下文策略](https://github.com/kaitranntt/ccs/blob/main/src/auth/account-context.ts) 也提供账户身份与工作配置分离的参考。

本项目借鉴“使用官方 CLI 登录、账户身份与共享配置分离、明确手动选择”的原则。实现方式是窄范围保存和恢复账户字段，保留现有配置目录；不会照搬 CCS 的目录隔离、符号链接、代理、后台刷新、用量轮询、环境变量清理或自动轮换。

CC Switch 主要解决供应商配置和本地代理管理，超出本项目的原生订阅账户手动切换范围。

## 已知问题与回归场景

| 公开记录 | 核查时状态与影响 | 本项目需要防止的场景 |
| --- | --- | --- |
| claude-swap [#383](https://github.com/realiti4/claude-swap/issues/383) | 未关闭；OAuth 缺失的活动存储覆盖账户备份，丢失刷新凭据 | 拒绝以缺少有效账户字段的活动状态覆盖已有账户快照 |
| claude-swap [#381](https://github.com/realiti4/claude-swap/issues/381) | 未关闭；嵌套会话刷新撤销默认登录凭据 | 不主动兑换刷新令牌；切换前停止使用旧身份的 Claude 进程 |
| claude-swap [#415](https://github.com/realiti4/claude-swap/issues/415) | 未关闭；用量轮询退避阻断闲置账户刷新，最终 `invalid_grant` | 不添加后台刷新或用量轮询；明确快照无法保证永久有效 |
| CCS [#1756](https://github.com/kaitranntt/ccs/issues/1756) | 未关闭；共享插件符号链接不断生成恢复文件 | 不重建共享配置目录或插件符号链接 |
| CCS [#622](https://github.com/kaitranntt/ccs/issues/622) | 已关闭；第三方 Google Antigravity OAuth 的封号警告 | 排除第三方 OAuth 代理；这不是原生 Claude 登录封号的证据 |
| CC Switch [#3519](https://github.com/farion1231/cc-switch/issues/3519) | 已关闭；用户担忧自动查询用量时的 IP／区域风险 | 不自动请求用量接口；该记录是风险担忧，不能当作已证实封号事件 |

这些场景是设计及验证目标，不能把表格理解为已经完成所有回归测试；实际验证见 [兼容性说明](compatibility.md)。

## 官方接口依据

登录与会话恢复的用户接口参考 [Claude Code 认证文档](https://code.claude.com/docs/en/authentication)及 [CLI 文档](https://code.claude.com/docs/en/cli-reference)。账户文件字段和 Keychain 名称仍属于内部格式，不视为官方兼容性承诺。

macOS 实现核对了 Apple 开源 [security 命令实现](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/security.c)与 [Keychain Item 实现](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Item.cpp)。前者存在交互输入长度限制；后者在更新内容时会重建存储组及其分区访问规则。因此大凭据不能仅验证写入成功，还必须验证官方 `security` 命令可继续读取。项目调用系统接口，不复制 Apple 实现源码。
