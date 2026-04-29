# SSH Config 管理工具方案文档

## 1. 背景

目标是做一个跨平台的 SSH Config 管理工具，主要解决以下问题：

- 频繁接触多种设备和环境，手动维护 `~/.ssh/config` 成本高。
- 设备类型多，配置组合多，经常重复录入相同字段。
- 需要兼顾 Windows 10 和 Ubuntu 的使用体验。
- 需要支持通配 Host、跳板、端口转发、老旧算法兼容、非标准私钥路径等实际场景。
- 后续希望围绕具体目标机，继续扩展到公钥下发和 `authorized_keys` 相关辅助能力。

本工具 Phase 1 先解决 SSH Config 的增删改查、组织和可视化管理问题；远端公钥下发不在首版交付范围内，但设计上提前预留。

## 2. 已确认决策

- 产品形态：CLI + TUI 混合
- 实现语言：Rust
- 配置布局：使用 `Include ~/.ssh/config.d/*`
- 可接受调整现有 `~/.ssh/config`
- 首批内置模板：
  - 嵌入式/频繁刷机
  - 老设备（legacy SSH）
  - VPS / serv00
  - 家里跳板内网
  - 本地端口转发
- Phase 2 暂不做公钥下发，只预留设计接口

## 3. 设计目标

### 3.1 功能目标

- 解析现有 SSH 配置
- 以结构化方式管理 Host 条目
- 支持精确 Host 和通配 Host
- 支持“原文视图”和“合并视图”
- 支持模板快速建条目
- 支持安全写入、自动备份、回滚基础能力
- 跨平台运行于 Windows 10 和 Ubuntu

### 3.2 非功能目标

- 不要求依赖 Python 运行时
- 可构建为单二进制分发
- 尽量不破坏用户已有的手工配置
- 写入行为可预测、顺序稳定、结果可读

### 3.3 非目标

- Phase 1 不做远端执行命令
- Phase 1 不直接修改目标机的 `authorized_keys`
- Phase 1 不追求完整覆盖 OpenSSH 所有指令
- Phase 1 不做云端同步或多机共享状态

## 4. 用户场景

### 4.1 日常维护

用户需要快速查看有哪些 Host、哪些使用了跳板、哪些开启了 legacy 算法、哪些设备使用了某个私钥。

### 4.2 快速新建设备

用户新增一个嵌入式设备时，希望通过模板快速生成条目，只补 `Host`、`HostName`、`IdentityFile` 等必要字段。

### 4.3 查看实际生效配置

对于 `bs-*` 这类通配规则，用户希望在查看 `bs-215` 时看到它最终继承了哪些参数，而不是只看到当前块里手写了什么。

### 4.4 配置安全落盘

用户希望每次修改前有备份，避免误改导致现有 SSH 工作流中断。

## 5. 范围定义

### 5.1 Phase 1

- `list` / 搜索 / 过滤
- `show` 查看条目
- `show --merged` 查看合并结果
- `add` / `edit` / `delete`
- 模板创建
- 自动备份
- 配置校验
- 初始化 `Include` 布局
- 可选迁移已有 Host 块到 `config.d`
- TUI 浏览与编辑

### 5.2 Phase 2 预留

- 根据 Host 元数据辅助生成公钥部署命令
- 根据目标系统提示 `authorized_keys` 路径和权限
- 根据连接方式推导远端用户家目录、SSH 目录权限修复建议

## 6. 配置与目录布局

建议采用以下目录结构：

```text
~/.ssh/
  config
  config.d/
    010-pattern-bs-star.conf
    020-host-bs-215.conf
    021-host-bs-212.conf
  .sshcfg/
    state.toml
    backups/
      config.20260420-101530.bak
      config.d.20260420-101530.zip
```

Windows 下等价路径为：

```text
%USERPROFILE%\.ssh\
```

### 6.1 根配置文件策略

根 `config` 只做三件事：

- 保留用户原有的全局配置和非托管内容
- 插入或维护一个受控的 `Include ~/.ssh/config.d/*`
- 尽量不重排用户已有内容

建议写入如下受控区块：

```sshconfig
# >>> sshcfg managed include >>>
Include ~/.ssh/config.d/*
# <<< sshcfg managed include <<<
```

这样后续工具只维护这个受控区块，不全量重写根文件。

### 6.2 `config.d` 命名策略

使用有序前缀保证 OpenSSH 读取顺序稳定：

```text
NNN-{kind}-{slug}.conf
```

示例：

- `010-pattern-bs-star.conf`
- `020-host-bs-215.conf`
- `030-host-home-router.conf`

原因：

- SSH Config 的匹配结果与文件顺序强相关
- 通配规则、精确规则、默认规则的前后顺序必须可控
- TUI 中支持调整顺序时，只需改序号并重写文件名

## 7. 数据模型

Phase 1 推荐把“SSH 配置数据”和“工具元数据”分开存储。

### 7.1 SSH 配置条目模型

每个条目对应一个 `Host` 块，字段包括：

- `host_patterns: Vec<String>`
- `hostname: Option<String>`
- `user: Option<String>`
- `port: Option<u16>`
- `proxy_jump: Option<String>`
- `identity_files: Vec<String>`
- `local_forwards: Vec<String>`
- `strict_host_key_checking: Option<String>`
- `user_known_hosts_file: Option<String>`
- `host_key_algorithms: Option<String>`
- `pubkey_accepted_algorithms: Option<String>`
- `forward_agent: Option<String>`
- `extra_options: Vec<(String, String)>`

说明：

- `HostName` 在精确 Host 场景通常必填；但对纯通配模板块可以允许为空。
- `IdentityFile` 设计为数组，兼容未来多私钥场景。
- `LocalForward` 为数组。
- `ForwardAgent` 先按字符串存储，兼容 `yes` / `no` 之外的扩展写法。
- 算法类字段先按原始字符串存储，避免过度解析。
- `extra_options` 用于保留扩展空间，例如后续支持 `RemoteForward`、`ServerAliveInterval`。

### 7.2 工具元数据模型

工具元数据不写进 SSH Config 本身，放到 `~/.ssh/.sshcfg/state.toml`，建议包含：

- 条目唯一 ID
- 文件顺序
- 条目类型：`host` / `pattern`
- 模板来源
- 标签
- 最近修改时间
- 备注
- 未来预留：
  - `target_os`
  - `remote_user_home`
  - `authorized_keys_path`
  - `ssh_dir_mode`
  - `authorized_keys_mode`

原因：

- 这些信息不属于标准 SSH Config 指令
- 为后续公钥辅助功能留位置
- 避免用注释污染配置文件

## 8. OpenSSH 语义与合并视图

这是本工具最关键的设计点之一。

### 8.1 需要支持两种视图

#### 原文视图

展示条目在文件中的真实内容和顺序，便于理解“到底写了什么”。

#### 合并视图

以一个目标 Host 别名为输入，按 SSH Config 实际匹配逻辑给出最终生效结果，包括：

- 命中了哪些 `Host` 块
- 命中顺序
- 每个字段来自哪个文件、哪个块
- 哪些值是继承得到的

### 8.2 顺序与优先级

SSH Config 是顺序敏感的，尤其是下面这种情况：

```sshconfig
Host bs-*
  User builder

Host bs-215
  HostName 172.16.0.215
```

对 `bs-215` 来说：

- 会同时命中 `bs-*` 和 `bs-215`
- 某些字段来自前面的通配块
- 如果后面的精确块试图覆盖同一个“先前已确定”的标量字段，结果可能和直觉不一致

因此工具需要：

- 明确显示命中链路
- 在编辑器里提示“该字段可能被前序规则锁定”
- 支持调整条目顺序

### 8.3 MVP 合并算法

内部实现上，合并器需要：

1. 按 `config` 和 `config.d/*` 的实际顺序遍历
2. 找出与目标 Host 匹配的块
3. 记录命中的块和字段来源
4. 对标量字段按 OpenSSH 语义求最终值
5. 对多值字段按规则累积

Phase 1 先对工具主动管理的字段给出稳定语义；若遇到无法可靠推断的复杂自定义字段，在合并视图中标记为“原样保留，未参与智能合并”。

## 9. CLI 与 TUI 形态设计

### 9.1 CLI 负责什么

CLI 适合：

- 脚本化
- 快速查询
- 单次修改
- 初始化和迁移
- 做 `doctor`/`validate`

建议命令：

```text
sshcfg init
sshcfg init --migrate
sshcfg list
sshcfg list --pattern bs-*
sshcfg show bs-215
sshcfg show bs-215 --merged
sshcfg add
sshcfg edit bs-215
sshcfg delete bs-215
sshcfg template list
sshcfg validate
sshcfg doctor
sshcfg tui
```

建议行为：

- 无参数启动时直接进入 TUI
- 明确查询场景优先保留 CLI

### 9.2 TUI 负责什么

TUI 适合：

- 浏览大量 Host
- 对比继承关系
- 新建和编辑多个字段
- 调整条目顺序
- 基于模板快速创建

建议 TUI 布局：

- 左侧：Host 列表 / 搜索 / 标签过滤
- 右侧上半：当前条目详情
- 右侧下半：原文视图 / 合并视图切换
- 底部：快捷键提示

建议快捷动作：

- `a` 新增
- `e` 编辑
- `d` 删除
- `v` 切换视图
- `t` 套用模板
- `r` 调整顺序
- `/` 搜索
- `b` 查看备份记录

## 10. 模板设计

首批模板如下。

### 10.1 嵌入式 / 频繁刷机

默认填充：

```sshconfig
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
```

### 10.2 老设备（legacy SSH）

默认填充：

```sshconfig
StrictHostKeyChecking no
UserKnownHostsFile /dev/null
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
```

### 10.3 VPS / serv00

默认填充：

```sshconfig
IdentityFile <用户选择>
```

### 10.4 家里跳板内网

默认填充：

```sshconfig
ProxyJump <用户选择的跳板 Host>
```

### 10.5 本地端口转发

默认填充：

```sshconfig
LocalForward <可新增多条>
```

模板实现建议：

- 模板本身用 `TOML` 或内置静态数据描述
- 支持模板 + 手工补充字段
- 支持“从现有 Host 另存为模板”作为后续增强项

## 11. 初始化与迁移策略

不建议首版直接强制迁移所有已有 Host 块，风险偏高。建议拆成两步。

### 11.1 `init`

执行内容：

- 检测 `~/.ssh/config` 是否存在
- 自动备份
- 如果缺少受控 `Include` 区块，则插入
- 创建 `config.d/` 和 `.sshcfg/` 目录
- 不主动迁移已有 Host 块

这样最安全，先让工具能接管新增条目。

### 11.2 `init --migrate`

显式触发迁移时：

- 再次备份
- 尝试解析根 `config` 中的 `Host` 块
- 将可识别的 Host 块拆分到 `config.d/`
- 保留根文件中的全局配置和无法安全迁移的内容
- 输出迁移报告

迁移失败策略：

- 任一关键阶段失败时停止写入
- 允许用户一键恢复最近备份

## 12. 写入、备份与校验

### 12.1 写入原则

- 先生成目标内容
- 先校验，再落盘
- 落盘采用临时文件 + 原子替换
- 所有写入前先备份

### 12.2 备份策略

每次变更前：

- 备份根 `config`
- 备份整个 `config.d/`
- 记录时间戳

备份位置：

```text
~/.ssh/.sshcfg/backups/
```

### 12.3 校验策略

Phase 1 校验至少包含：

- Host 名称不能为空
- 精确 Host 必须有 `HostName`
- `Port` 合法
- `LocalForward` 基本格式正确
- `IdentityFile` 路径非空
- 文件顺序无重复号段
- 受控区块存在且唯一

可选增强：

- 如果本机存在 `ssh` 命令，可调用 `ssh -G <host>` 做外部一致性校验
- 对 legacy 算法字段给出风险提示，但不阻止保存

## 13. 跨平台要求

### 13.1 路径

- Windows：`%USERPROFILE%\\.ssh\\config`
- Linux：`~/.ssh/config`

### 13.2 换行

- 读取时兼容 `CRLF` / `LF`
- 写回时默认使用目标平台原生换行风格

### 13.3 权限

- Linux 写入后确保关键文件权限合理
- Windows 不强制设置额外 ACL

### 13.4 `IdentityFile`

- 存什么写什么，不做路径转换
- 允许 Windows 风格路径和 Linux 风格路径共存

## 14. Rust 技术方案

建议技术栈如下：

- CLI：`clap`
- TUI：`ratatui` + `crossterm`
- 错误处理：`anyhow` 或 `miette`
- 序列化：`serde` + `toml`
- 路径与用户目录：`directories`
- 时间戳：`chrono`
- 文件匹配：标准库 + 轻量匹配逻辑

### 14.1 模块划分建议

```text
src/
  main.rs
  app/
    cli.rs
    commands/
      init.rs
      list.rs
      show.rs
      add.rs
      edit.rs
      delete.rs
      validate.rs
      doctor.rs
  core/
    model.rs
    parser.rs
    render.rs
    resolve.rs
    validate.rs
    template.rs
  fs/
    layout.rs
    backup.rs
    writer.rs
  tui/
    app.rs
    state.rs
    views/
      host_list.rs
      detail.rs
      editor.rs
      merged.rs
```

### 14.2 一个重要取舍

首版不要追求“无损 round-trip 任意 SSH Config 语法树”。更稳妥的做法是：

- 根 `config` 最少改动
- 工具托管内容全部放在 `config.d`
- 工具写出的托管文件采用统一格式
- 对不受控文件只读不写

这样可以显著降低解析和回写复杂度。

## 15. Phase 2 预留设计

虽然暂不实现公钥下发，但建议在模型和 UX 上预留以下能力。

### 15.1 预留元数据

针对具体 Host，可额外记录：

- 目标系统类型：`debian` / `ubuntu` / `centos7` / `openwrt` / `other`
- 远端登录用户
- 远端家目录
- 远端 SSH 目录
- `authorized_keys` 路径
- 目录和文件权限要求

### 15.2 未来可能的辅助输出

例如用户选中 `bs-215` 后，工具未来可以输出：

- 应该把公钥追加到哪个文件
- 需要执行哪些 `mkdir/chmod/chown`
- 不同系统下的注意事项
- 是否适合使用 `ssh-copy-id` 或自定义一键命令

### 15.3 为什么现在就预留

因为这类信息不适合直接塞进 SSH Config 字段，但又和具体 Host 强相关，提前把元数据存储位置设计好，后续扩展会顺很多。

## 16. MVP 里程碑建议

### Milestone 1

- `init`
- `list`
- `show`
- `add`
- `delete`
- 模板
- 备份
- 基础校验

### Milestone 2

- `edit`
- `show --merged`
- TUI 浏览器
- 搜索与过滤
- 条目顺序调整

### Milestone 3

- `init --migrate`
- `doctor`
- 更完整的导入与错误提示
- 未来 Phase 2 元数据落盘框架

## 17. 风险与注意事项

- OpenSSH 配置顺序敏感，通配和精确 Host 的覆盖关系必须做清楚提示。
- 如果用户手动修改 `config.d` 中的托管文件，工具需要决定是完全接受、还是在保存时重排并格式化。首版建议“接受内容，但按工具格式重写”。
- 对复杂自定义字段的“真实生效语义”不一定都能完整复现，合并视图需明确标识能力边界。
- 自动迁移旧配置时，评论、空行和历史手工组织方式可能无法 100% 保真。

## 18. 建议的首版结论

从实现成本、风险和用户收益来看，首版建议采用以下落地策略：

1. 先实现“工具管理 `config.d`，根 `config` 只维护 `Include`”。
2. 先把新建、查看、删除、模板、合并视图做稳。
3. 迁移旧配置放到显式命令里，不放在默认首次启动流程。
4. 元数据单独存储，为未来公钥辅助功能预留空间。
5. TUI 以浏览和编辑为主，CLI 负责自动化和精确操作。

这条路径最稳，也最符合当前需求优先级。
