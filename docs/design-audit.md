# sshcfg 设计审查与改进清单

**审查日期：** 2026-04-30
**审查范围：** `src/` 全部源码（约 17,500 行 Rust）
**审查方法：** 静态阅读 + 代码搜索；未运行动态/性能/模糊测试

本文档记录当前实现中发现的设计缺陷与不足，按维度分组，每条都给出文件、行号与简短理由。文末附**优先级建议**与**修复路线图**，可作为后续迭代的 backlog。

---

## 1. 原子写与并发安全（高优先级）

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 1.1 | 非原子的 `remove + rename` | `src/fs/writer.rs:29-33` | Unix 上 `fs::rename` 本身覆盖原子，先 `exists()` + `remove_file` 把"原子替换"拆为"删除→改名"，崩溃后留下无文件状态；同时存在 TOCTOU。建议直接 `fs::rename(temp, path)`，让平台处理覆盖。 |
| 1.2 | 缺文件锁 | 全代码无 `flock` / `fs2` / `fd-lock` | 两个并发的 `sshcfg add` / `edit` 共享读 `config.d/`，各自做 backup 与写入，结果与 `state.toml` 都会丢更新。建议在 `AppPaths::discover()` 取一次 `~/.ssh/.sshcfg/.lock` 的独占锁，整个命令期间持有。 |
| 1.3 | 重写 `config.d` 的崩溃残留 | `src/core/store.rs:113-158`、`src/fs/backup.rs:206-235` | 流程是 `rename(config.d → retired); rename(staging → config.d); remove_dir_all(retired)`。两次 rename 之间崩溃会让 `config.d` 消失，残留 `.config.d.retired-PID-…` 不会自动恢复。建议启动时清理/恢复，或在 Linux 上改用 `renameat2(RENAME_EXCHANGE)`。 |
| 1.4 | 缺 `fsync(parent_dir)` | `src/fs/writer.rs`、`src/fs/backup.rs` | 所有原子写都未同步父目录条目，断电可能丢失 rename 结果。建议写后 `File::open(parent)?.sync_all()`。 |
| 1.5 | 静默吞错 | `src/fs/backup.rs:225-227`、`src/fs/writer.rs` 周边 | 多处 `let _ = std::fs::rename(...)` / `let _ = remove_file(...)` 静默忽略回滚失败，留下不一致状态且无任何告警。 |
| 1.6 | 符号链接未处理 | `src/fs/layout.rs:71-88`、`src/fs/writer.rs:26` | 列 `*.conf` 时未检测 symlink；`fs::write` 会沿链接写入。期望托管目录里的文件就是普通文件，应在 `managed_entry_files` 里 `is_symlink()` 检测并拒绝/警告。 |
| 1.7 | 目录权限缺省 | `src/fs/layout.rs:44-50` | `create_dir_all` 未设 `0o700`；只有文件被设为 `0o600`（`writer.rs:42`）。`~/.ssh/.sshcfg/` 与 `backups/` 应同样收紧到 `0o700`。 |
| 1.8 | `unwrap_or_default()` 隐藏失败 | `src/fs/writer.rs:22` `timestamp_nanos_opt().unwrap_or_default()` | 时钟异常时 fallback 到 0，让 temp 文件名跨进程冲突。建议 fallback 到 `Instant`/PID+计数器。 |

---

## 2. 解析器/渲染器正确性

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 2.1 | `Key=Value` 与引号未支持 | `src/core/parser.rs:94-102` | `split_key_value` 仅按空白切分。OpenSSH 合法的 `Key=Value`、引号包裹带空格的值（`IdentityFile "C:/Program Files/.ssh/id"`）都不被支持。`render.rs` 也不会自动加引号——含空格的路径写出后再读回会错位。 |
| 2.2 | 不支持 `Include` | `src/core/parser.rs:32-84` | 托管文件里出现 `Include` 会被默默归到 `extra_options`，破坏托管语义。建议显式拒绝或显式声明不支持。 |
| 2.3 | 不支持托管文件中的 `Match` | `src/core/parser.rs:32-52` | 是显式约束，但 `init --migrate` 从根 config 迁移时遇到 `Match` 会被 skip，README/帮助里没明示这一点。 |
| 2.4 | 未识别关键字静默归到 `extra_options` | `src/core/parser.rs:81-83` | 没有拼写检查，`HostNme` 会作为自定义字段保留，渲染时原样写出，让用户调试很难。建议至少 `doctor` 报告 unknown keyword 数量。 |
| 2.5 | Tokens（`%h %p %r`）零处理 | `src/app/commands/validate.rs:1065+` | 路径归一化是纯字符串处理，含 token 的值与 `ssh -G` 展开后不会匹配，徒增 mismatch 噪声。 |
| 2.6 | 渲染器不引号化 | `src/core/render.rs:53-65` | 任何字段值含空白都直接 `format!("{key} {value}{newline}")`。round-trip 后语义会丢失。 |

---

## 3. 解析合并 / 校验

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 3.1 | `StrictHostKeyChecking` 允许列表错误 | `src/core/validate.rs:60-69` | 把 `true`/`false`/`on` 加入合法值，OpenSSH 实际只接受 `yes/no/ask/off/accept-new`。 |
| 3.2 | Host pattern 用 glob 字符类 | `src/core/resolve.rs:755-772` | 使用 `glob::Pattern`，`*`/`?` 与 OpenSSH 兼容，但 glob 的 `[abc]` 字符类 OpenSSH 不支持——出现方括号会被当成字符类，与真实 ssh 行为不同。建议自实现简版 matcher。 |
| 3.3 | `apply_scalar_*` 重复样板 | `src/core/resolve.rs:573-700` 等 | 八个 scalar 字段每个都展平成独立函数调用（约 90 行重复样板）。每加一个字段要改 6 处（`resolve` / `render` / `parser` / `edit` / `add` / `cli`）。建议抽象为"字段表 × 行为"驱动表。这也是 `core/resolve.rs` 体量 1362 行的主因。 |
| 3.4 | `detect_local_networks()` 无缓存 | `src/core/resolve.rs:36-37`、`src/core/root_config.rs:795-801` | 每次 resolve 都 fork 子进程，TUI 里高频 `reload_preserving` 会反复 spawn。`ssh_version` 已用 `OnceLock` 缓存（`openssh.rs:38`），networks/local_user 也应同样缓存。 |

---

## 4. 模块体量 / 耦合

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 4.1 | `tui/state.rs` god-object | `src/tui/state.rs`（2,468 行） | `TuiState` 单 impl 含 123 个方法，所有模式（`Search` / `Filter` / `Inspect` / `BackupCatalog` / `ConfirmDelete` / `ConfirmRestore` / `Edit` / `Reorder`）都塞进同一个结构。建议每个 `InputMode` 抽出独立子状态结构，`TuiState` 持枚举。 |
| 4.2 | `commands/validate.rs` 巨型文件 | `src/app/commands/validate.rs`（2,153 行） | `normalize_*`、`compare_*`、`run_ssh_g` 编排、ssh -G 输出比对全部混在同层。至少应拆出 `validate/normalize.rs` 与 `validate/diff.rs`。 |
| 4.3 | 命令文件交互式补全重复 | `commands/{order,edit,init,add,duplicate}.rs`（合计 ~3,800 行） | 四个文件都把"参数解析→交互式补全→落盘→输出"放一起；交互式补全（`prompt_*`）是最大的重复子模块，应抽到 `app/interactive/`。 |
| 4.4 | `core/root_config.rs` 混职责 | `src/core/root_config.rs`（1,455 行） | 同时承担：①Match block tokenizing、②Match condition 求值、③本机 IP/用户/版本探测。`detect_local_networks`、`detect_local_username` 应另起 `core/sysprobe.rs`。 |

---

## 5. 错误处理

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 5.1 | 生产路径基本无 `unwrap`/`panic` | — | 主流程基本依赖 `anyhow::Context`；非测试代码里未发现 `unwrap()`/`expect()`/`panic!`。✅ |
| 5.2 | TUI 错误仅落 status bar | `src/tui/app.rs:93,105,234,251` 等 | 错误展示给底部状态栏，用户可能错过；没有持久化错误日志。建议同时写入 `~/.ssh/.sshcfg/sshcfg.log`。 |
| 5.3 | TUI 缺 panic guard | `src/tui/app.rs:18-25` | 一旦 panic，`disable_raw_mode` 与 `LeaveAlternateScreen` 不会被调用，终端被搞坏。应在 `init_terminal` 后立即注册 `panic::set_hook` 还原。 |

---

## 6. 测试覆盖

| # | 标签 | 描述 |
|---|---|---|
| 6.1 | 缺顶层 `tests/` | 所有测试是内联单元测试（AGENTS.md 已承认）。无黑盒集成测试。 |
| 6.2 | 关键模块零覆盖 | `src/fs/writer.rs`（0 测试，关键路径）、`src/core/render.rs`（0）、`src/tui/views/*`、`src/app/cli.rs`、`src/app/commands/{list,template,show,tui}.rs`。 |
| 6.3 | 缺并发/崩溃恢复测试 | 没有针对并发写、断电中断、跨平台行尾的测试；没有 fuzz 解析器。 |

---

## 7. CLI / UX 不一致

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 7.1 | `--ssh-tag` 与 `--tag` 同时存在 | `src/app/cli.rs:238,254` 等 | `Tag`（OpenSSH 指令）与 metadata 标签是两个不同概念，但 CLI 上一个叫 `--ssh-tag`、一个叫 `--tag`，容易混。考虑文档里专门解释一段。 |
| 7.2 | `--clear-*` 镜像爆炸 | `src/app/cli.rs:266-383` | `edit` 几乎每个字段都有 `--clear-X` 镜像（约 18 对），手感冗长，且 `--clear-template` / `--template` 之间的冲突只靠运行时 `bail!` 检测，未在 clap `ArgGroup` 里声明。 |
| 7.3 | `--all` 与 filter 互斥 | `src/app/commands/order.rs`、`delete.rs` | 互斥关系在 `validate_*_args` 运行时报错，应改用 clap `ArgGroup`，让冲突在解析阶段就阻止。 |

---

## 8. TUI

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 8.1 | UI 线程阻塞 spawn | `src/tui/app.rs:46-50`、状态机里的 `V`/`D` 键 | `event::poll(250ms)` 单线程；`V` 键的 `validate --ssh-g` 逐 host spawn `ssh -G` 同步等待，期间 UI 完全冻结、无进度反馈。建议把校验/doctor 移到线程并通过 channel 推回状态。 |
| 8.2 | 无 panic 还原 | `src/tui/app.rs:18-25` | 见 5.3。 |
| 8.3 | 全量 reload | `tui/state.rs::load_snapshot` | 每次 reload 重读所有 `.conf` 与 metadata，无增量。在大量 host 时可见。可考虑 mtime 缓存。 |

---

## 9. 其他

| # | 标签 | 位置 | 描述 |
|---|---|---|---|
| 9.1 | 三个空模板 | `src/core/template.rs:31-33,101` | `Vps`/`Jump`/`Forward` 是空 `[(&str,&str); 0]`，`apply_template` 对它们 no-op；TUI/CLI 里仍可选——对用户像"假按钮"。要么填充内容，要么先移除直到有真实预设。 |
| 9.2 | 备份保留数硬编码 | `src/fs/backup.rs:9` `DEFAULT_BACKUP_RETENTION = 30` | 无 CLI、无环境变量、无 `state.toml` 字段。建议放进 `state.toml`。 |
| 9.3 | 备份按字典序排 | `src/fs/backup.rs:128` | 依赖时间戳格式 `YYYYMMDD-HHMMSS-fff`；用户手动 rename 一个目录就排序错。建议改用文件 mtime 或显式 metadata。 |
| 9.4 | 单文件错全盘失败 | `src/core/store.rs:225-243` `parse_order_and_slug` | 手动放入 `myhost.conf`（不符合 `NNN-kind-slug.conf` 格式）会让 `load_managed_entries` 整体 `bail!`，一个坏文件让 `list`/`edit`/`show` 全挂。建议跳过+警告。 |
| 9.5 | 慢路径无并发 | `src/app/commands/validate.rs` ssh -G 调用 | 30+ host 时串行 `ssh -G`，几秒到十几秒。可用 `rayon` / 线程池并发。 |
| 9.6 | CRLF round-trip 无测试 | `src/fs/layout.rs:91-101` `platform_newline` / `detect_newline` | Windows 上 `\r\n`，Linux 上 `\n`；测试里都只用 `\n`，没有 CRLF round-trip 验证。 |

---

## 优先级建议

按"风险 / 工作量"评估，建议这样排：

### P0 — 数据安全（半天到一天）
- **1.2** 加文件锁
- **1.1** 修 `writer.rs` 的非原子 `remove + rename`
- **1.4** `fsync(parent_dir)`
- **3.1** 修 `StrictHostKeyChecking` 白名单
- **5.3** TUI panic guard

### P1 — 正确性 / 一致性（1-2 天）
- **1.3** 启动时清理 `.config.d.retired-*` / `.staging-*` 残留
- **2.1** 解析器支持引号 + `Key=Value`
- **2.6** 渲染器在值含空白时自动加引号
- **9.4** `parse_order_and_slug` 失败应跳过+警告

### P2 — 性能 / 体验（2-3 天）
- **3.4** 缓存 `detect_local_networks` / `detect_local_username`
- **8.1** TUI 异步执行 validate / doctor
- **9.5** ssh -G 并发

### P3 — 重构（按需）
- **4.1** 拆分 `tui/state.rs`（按 `InputMode` 切子状态）
- **4.2** 拆分 `commands/validate.rs`
- **4.3** 抽出 `app/interactive/`
- **3.3** scalar 字段表驱动化

### P4 — 长期
- **6.x** 顶层 `tests/` 集成测试 + 解析器 fuzz
- **9.1** 三个空模板要么填充要么删除

---

## 修复时的注意事项

- **数据安全相关改动（P0）必须配套测试**：尤其 `writer.rs` / `backup.rs`，要覆盖崩溃中断、并发写、Windows 行为。
- **解析器变更（P1 2.x）需向前兼容旧文件**：现网用户的 `config.d/*.conf` 多半是 `Key Value` 简单形式，新版必须保留 round-trip。
- **TUI 重构（P3 4.1）建议分阶段**：先抽 `Search`/`Filter` 这类只读模式，再处理 `Edit`/`Reorder` 这些状态依赖更深的模式。
- **不要为这次审查所列项一次性 PR**：每条按 P 级别独立 PR，方便 review 与回滚。
