# sshcfg

`sshcfg` is a user-facing SSH config manager for people who keep many hosts, jump boxes, and port-forward profiles.

It stores managed entries under `~/.ssh/config.d/`, keeps a controlled include block in `~/.ssh/config`, and adds safer workflows for add/edit/duplicate/reorder/validate without forcing you to hand-edit one large config file.

## Why Use It

- Keep one managed host entry per file instead of one giant `~/.ssh/config`
- Duplicate similar hosts quickly when you are bringing up another box with nearly the same settings
- Reorder entries safely without manually renaming files
- Validate managed entries before they break your SSH flow
- Keep automatic backups before write operations
- Browse and edit managed entries from a TUI when CLI flags get tedious

## Install

### Option 1: Use a prebuilt binary

This is the path for normal end users. Rust is not required.

1. Get a prebuilt `sshcfg` binary from your release artifact, internal share, or download page.
2. Put it somewhere on your `PATH`.

Examples:

- Windows: place `sshcfg.exe` in a directory that is already on `PATH`
- Ubuntu/Linux: `chmod +x sshcfg` and move it to `~/.local/bin/` or `/usr/local/bin/`

### Option 2: Build from source

Use this if you are developing the tool or do not have a packaged binary yet.

```bash
cargo build --release
```

The resulting binary is:

- Windows: `target/release/sshcfg.exe`
- Linux: `target/release/sshcfg`

## Requirements

- OpenSSH `ssh` on `PATH` if you want `validate --ssh-g`
- Windows 10 and Ubuntu/Linux builds have been verified

## First Run

Initialize the managed layout once:

```bash
sshcfg init
```

This creates:

```text
~/.ssh/
  config
  config.d/
  .sshcfg/
    backups/
    state.toml
```

`sshcfg` keeps a managed include block in `~/.ssh/config` and writes managed entries to `config.d/`.

## Common Workflows

### Add a host

```bash
sshcfg add server-a --hostname 10.0.0.10 --user root
```

If the target itself is an IP or FQDN, you can use the short form:

```bash
sshcfg add 172.16.7.226
```

### Duplicate a similar host

This is useful when you are configuring another device that is almost the same as an existing one.

```bash
sshcfg duplicate server-a server-b --hostname 10.0.0.11
sshcfg duplicate 172.16.7.226 172.16.7.227
```

If you intentionally want the new alias to keep the same `HostName`, use:

```bash
sshcfg duplicate jump-a jump-b --keep-hostname
```

### Inspect and validate

```bash
sshcfg list
sshcfg show server-a
sshcfg show server-a --merged
sshcfg validate
sshcfg validate --ssh-g
sshcfg doctor
```

### Edit, reorder, and delete

```bash
sshcfg edit server-a
sshcfg order server-a --before jump-a
sshcfg delete server-a
```

### Use the TUI

```bash
sshcfg tui
```

## Safety Model

- Managed content lives in `~/.ssh/config.d/`
- The root `~/.ssh/config` is only adjusted to keep the managed include block in place
- Backups are created before write operations
- Recent backup snapshots are retained automatically
- `validate --ssh-g` can compare exact managed hosts against local OpenSSH resolution

## Common Commands

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

## Notes

- `show --merged` can simulate root `Match` context with `--match-tag`, `--match-user`, `--match-local-user`, `--match-ssh-version`, `--match-session-type`, `--match-command`, `--match-local-network`, `--match-canonical`, and `--match-non-final`
- Complex OpenSSH `Match` forms are still handled conservatively

## Documentation

- [Chinese README](docs/README.zh-CN.md)
- [Implementation plan](docs/implementation-plan.md)
