# sshcfg

`sshcfg` 是一个给终端用户用的 SSH 配置管理工具，适合手上机器很多、跳板很多、端口转发很多的人。

它会把托管条目放到 `~/.ssh/config.d/`，在 `~/.ssh/config` 里维护一个受控 include block，并提供比手改大文件更稳的 add / edit / duplicate / order / validate 工作流。

## 适合拿它来做什么

- 把托管 SSH 条目拆成一个 Host 一个文件
- 新设备和旧设备配置很像时，直接复制已有条目再改一点点
- 安全调整规则顺序，不用手工改文件名
- 在写回前做校验，减少把 SSH 配坏的概率
- 每次改写前自动留备份
- CLI 参数嫌麻烦时，直接进 TUI 浏览和编辑

## 安装

### 方案 1：直接用预编译二进制

这是普通使用者最合适的方式，不需要 Rust 环境。

1. 从你的发布包、内部共享目录或下载页面拿到 `sshcfg` 二进制
2. 放到 `PATH` 里的某个目录

示例：

- Windows：把 `sshcfg.exe` 放到已经在 `PATH` 里的目录
- Ubuntu/Linux：先 `chmod +x sshcfg`，再放到 `~/.local/bin/` 或 `/usr/local/bin/`

### 方案 2：从源码构建

这个更适合开发者，或者你手上暂时还没有打包好的二进制。

```bash
cargo build --release
```

生成物位置：

- Windows：`target/release/sshcfg.exe`
- Linux：`target/release/sshcfg`

## 依赖

- 如果要用 `validate --ssh-g`，本机 `PATH` 里需要有 OpenSSH 的 `ssh`
- Windows 10 和 Ubuntu/Linux 的编译已经验证通过

## 第一次使用

先初始化一次托管布局：

```bash
sshcfg init
```

会创建：

```text
~/.ssh/
  config
  config.d/
  .sshcfg/
    backups/
    state.toml
```

`sshcfg` 会在 `~/.ssh/config` 里保留一个受控 include block，并把托管条目写到 `config.d/`。

## 常见用法

### 新增一个 Host

```bash
sshcfg add server-a --hostname 10.0.0.10 --user root
```

如果目标本身就是 IP 或 FQDN，也可以直接：

```bash
sshcfg add 172.16.7.226
```

### 复制一个相似设备

这正适合“新机器和老机器配置九成一样”的场景。

```bash
sshcfg duplicate server-a server-b --hostname 10.0.0.11
sshcfg duplicate 172.16.7.226 172.16.7.227
```

如果你就是想保留原来的 `HostName`，可以显式写：

```bash
sshcfg duplicate jump-a jump-b --keep-hostname
```

### 查看和校验

```bash
sshcfg list
sshcfg show server-a
sshcfg show server-a --merged
sshcfg validate
sshcfg validate --ssh-g
sshcfg doctor
```

### 编辑、重排、删除

```bash
sshcfg edit server-a
sshcfg order server-a --before jump-a
sshcfg delete server-a
```

### 使用 TUI

```bash
sshcfg tui
```

## 安全边界

- 托管内容放在 `~/.ssh/config.d/`
- 根 `~/.ssh/config` 只做最小改动，用来维持受控 include block
- 每次写入前会自动备份
- 旧备份会自动做保留数量清理
- `validate --ssh-g` 可以把 exact `Host` 和本机 OpenSSH 的解析结果做对比

## 常用命令

- `sshcfg init`
- `sshcfg init --migrate`
- `sshcfg list [--query ...] [--tag ...] [--has-note] [--template ...]`
- `sshcfg show <host>`
- `sshcfg show <host> --merged`
- `sshcfg add <host> ...`
- `sshcfg duplicate <source> <new-host> [--hostname ...]`
- `sshcfg edit <host> ...`
- `sshcfg order <host> ...`
- `sshcfg delete <host> ...`
- `sshcfg meta ...`
- `sshcfg validate [--ssh-g]`
- `sshcfg doctor`
- `sshcfg tui`

## 备注

- `show --merged` 可以配合 `--match-tag`、`--match-user`、`--match-local-user`、`--match-ssh-version`、`--match-session-type`、`--match-command`、`--match-local-network`、`--match-canonical`、`--match-non-final` 来模拟 root `Match` 上下文
- 更复杂的 OpenSSH `Match` 形式目前仍然是保守处理

## 相关文档

- [英文 README](../README.md)
- [方案文档](implementation-plan.md)
