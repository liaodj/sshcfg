use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Local;

use crate::fs::layout::AppPaths;
use crate::fs::writer;

const DEFAULT_BACKUP_RETENTION: usize = 30;

#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    pub path: PathBuf,
    pub label: String,
    pub has_root_config: bool,
    pub managed_file_count: usize,
}

#[derive(Debug, Clone)]
pub struct RestoreBackupOutcome {
    pub restored_snapshot: BackupSnapshot,
    pub pre_restore_backup_path: Option<PathBuf>,
}

pub fn retention_limit() -> usize {
    DEFAULT_BACKUP_RETENTION
}

pub fn create_backup(paths: &AppPaths) -> Result<Option<PathBuf>> {
    let root_exists = paths.root_config.exists();
    let config_dir_exists = paths.config_d_dir.exists();
    let config_dir_has_files =
        config_dir_exists && std::fs::read_dir(&paths.config_d_dir)?.next().is_some();

    if !root_exists && !config_dir_has_files {
        return Ok(None);
    }

    std::fs::create_dir_all(&paths.backups_dir)?;

    let stamp = Local::now().format("%Y%m%d-%H%M%S-%3f").to_string();
    let target_dir = paths.backups_dir.join(stamp);
    std::fs::create_dir_all(&target_dir)?;

    if root_exists {
        std::fs::copy(&paths.root_config, target_dir.join("config.bak"))?;
    }

    if config_dir_has_files {
        copy_dir_recursive(&paths.config_d_dir, &target_dir.join("config.d"))?;
    }

    prune_old_backups(&paths.backups_dir, DEFAULT_BACKUP_RETENTION)?;

    Ok(Some(target_dir))
}

pub fn list_backups(paths: &AppPaths) -> Result<Vec<BackupSnapshot>> {
    let mut snapshots = Vec::new();

    for path in snapshot_dirs(&paths.backups_dir)? {
        let label = snapshot_label(&path);
        let has_root_config = path.join("config.bak").exists();
        let managed_file_count = count_files_recursive(&path.join("config.d"))?;

        snapshots.push(BackupSnapshot {
            path,
            label,
            has_root_config,
            managed_file_count,
        });
    }

    Ok(snapshots)
}

pub fn restore_backup(paths: &AppPaths, snapshot: &BackupSnapshot) -> Result<RestoreBackupOutcome> {
    if !snapshot.path.exists() {
        bail!(
            "backup snapshot `{}` does not exist",
            snapshot.path.display()
        );
    }
    if !snapshot.path.is_dir() {
        bail!(
            "backup snapshot `{}` is not a directory",
            snapshot.path.display()
        );
    }

    let pre_restore_backup_path = create_backup(paths)?;

    restore_root_config(paths, &snapshot.path)?;
    restore_managed_dir(paths, &snapshot.path)?;

    Ok(RestoreBackupOutcome {
        restored_snapshot: snapshot.clone(),
        pre_restore_backup_path,
    })
}

fn prune_old_backups(backups_dir: &Path, keep_latest: usize) -> Result<Vec<PathBuf>> {
    let snapshots = snapshot_dirs(backups_dir)?;
    let mut removed = Vec::new();

    for path in snapshots.into_iter().skip(keep_latest) {
        std::fs::remove_dir_all(&path)?;
        removed.push(path);
    }

    Ok(removed)
}

fn snapshot_dirs(backups_dir: &Path) -> Result<Vec<PathBuf>> {
    if !backups_dir.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for item in std::fs::read_dir(backups_dir)? {
        let item = item?;
        let path = item.path();
        if path.is_dir() {
            snapshots.push(path);
        }
    }

    snapshots.sort_by(|left, right| snapshot_label(right).cmp(&snapshot_label(left)));
    Ok(snapshots)
}

fn snapshot_label(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("<unknown>")
        .to_string()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;

    for item in std::fs::read_dir(src)? {
        let item = item?;
        let path = item.path();
        let target = dst.join(item.file_name());

        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            std::fs::copy(path, target)?;
        }
    }

    Ok(())
}

fn count_files_recursive(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for item in std::fs::read_dir(path)? {
        let item = item?;
        let child = item.path();
        if child.is_dir() {
            count += count_files_recursive(&child)?;
        } else {
            count += 1;
        }
    }

    Ok(count)
}

fn restore_root_config(paths: &AppPaths, snapshot_dir: &Path) -> Result<()> {
    let snapshot_root = snapshot_dir.join("config.bak");
    if snapshot_root.exists() {
        copy_file_atomic(&snapshot_root, &paths.root_config)?;
    } else if paths.root_config.exists() {
        std::fs::remove_file(&paths.root_config)?;
    }

    Ok(())
}

fn restore_managed_dir(paths: &AppPaths, snapshot_dir: &Path) -> Result<()> {
    let snapshot_config_d = snapshot_dir.join("config.d");
    if snapshot_config_d.exists() {
        replace_dir_atomic(&snapshot_config_d, &paths.config_d_dir)?;
    } else if paths.config_d_dir.exists() {
        std::fs::remove_dir_all(&paths.config_d_dir)?;
    }

    Ok(())
}

fn copy_file_atomic(src: &Path, dst: &Path) -> Result<()> {
    let content = std::fs::read(src)
        .with_context(|| format!("failed to read snapshot file {}", src.display()))?;
    writer::write_bytes_file(dst, &content)
        .with_context(|| format!("failed to restore snapshot file {}", dst.display()))?;
    Ok(())
}

fn replace_dir_atomic(src: &Path, dst: &Path) -> Result<()> {
    let parent = dst
        .parent()
        .with_context(|| format!("managed directory has no parent: {}", dst.display()))?;
    let stamp = Local::now().format("%Y%m%d-%H%M%S-%3f").to_string();
    let staging_dir = parent.join(format!(
        ".config.d.restore-staging-{}-{stamp}",
        std::process::id()
    ));
    let retired_dir = parent.join(format!(
        ".config.d.restore-retired-{}-{stamp}",
        std::process::id()
    ));

    copy_dir_recursive(src, &staging_dir)?;

    if dst.exists() {
        std::fs::rename(dst, &retired_dir)?;
        if let Err(err) = std::fs::rename(&staging_dir, dst) {
            let _ = std::fs::rename(&retired_dir, dst);
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(err.into());
        }
        std::fs::remove_dir_all(&retired_dir)?;
    } else {
        std::fs::rename(&staging_dir, dst)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::fs::layout::AppPaths;

    use super::{
        BackupSnapshot, create_backup, list_backups, prune_old_backups, restore_backup,
        retention_limit,
    };

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-backups")
            .join(format!(
                "{name}-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));

        std::fs::create_dir_all(&root).unwrap();
        let ssh_dir = root.join(".ssh");
        let app_dir = ssh_dir.join(".sshcfg");
        AppPaths {
            ssh_dir: ssh_dir.clone(),
            root_config: ssh_dir.join("config"),
            config_d_dir: ssh_dir.join("config.d"),
            app_dir: app_dir.clone(),
            backups_dir: app_dir.join("backups"),
            state_file: app_dir.join("state.toml"),
        }
    }

    #[test]
    fn lists_backups_in_descending_label_order() {
        let paths = test_paths("list");
        std::fs::create_dir_all(
            paths
                .backups_dir
                .join("20260421-100000-000")
                .join("config.d"),
        )
        .unwrap();
        std::fs::create_dir_all(
            paths
                .backups_dir
                .join("20260421-110000-000")
                .join("config.d"),
        )
        .unwrap();
        std::fs::write(
            paths
                .backups_dir
                .join("20260421-110000-000")
                .join("config.bak"),
            "Host alpha\n",
        )
        .unwrap();
        std::fs::write(
            paths
                .backups_dir
                .join("20260421-110000-000")
                .join("config.d")
                .join("010-host-alpha.conf"),
            "Host alpha\n",
        )
        .unwrap();

        let backups = list_backups(&paths).unwrap();

        assert_eq!(backups.len(), 2);
        assert_eq!(backups[0].label, "20260421-110000-000");
        assert!(backups[0].has_root_config);
        assert_eq!(backups[0].managed_file_count, 1);
        assert_eq!(backups[1].label, "20260421-100000-000");
    }

    #[test]
    fn prunes_old_backups_beyond_limit() {
        let paths = test_paths("prune");
        for label in [
            "20260421-090000-000",
            "20260421-100000-000",
            "20260421-110000-000",
        ] {
            std::fs::create_dir_all(paths.backups_dir.join(label)).unwrap();
        }

        let removed = prune_old_backups(&paths.backups_dir, 2).unwrap();
        let backups = list_backups(&paths).unwrap();

        assert_eq!(removed.len(), 1);
        assert!(removed[0].ends_with("20260421-090000-000"));
        assert_eq!(backups.len(), 2);
        assert_eq!(backups[0].label, "20260421-110000-000");
        assert_eq!(backups[1].label, "20260421-100000-000");
    }

    #[test]
    fn create_backup_keeps_only_latest_snapshots() {
        let paths = test_paths("create-prune");
        std::fs::create_dir_all(&paths.config_d_dir).unwrap();
        std::fs::write(&paths.root_config, "Host alpha\n").unwrap();
        std::fs::write(
            paths.config_d_dir.join("010-host-alpha.conf"),
            "Host alpha\n  HostName alpha.example.com\n",
        )
        .unwrap();

        for index in 0..retention_limit() {
            std::fs::create_dir_all(
                paths
                    .backups_dir
                    .join(format!("20000101-0000{:02}-000", index)),
            )
            .unwrap();
        }

        let created = create_backup(&paths).unwrap().unwrap();
        let backups = list_backups(&paths).unwrap();

        assert_eq!(backups.len(), retention_limit());
        assert_eq!(backups[0].path, created);
        assert!(
            backups
                .iter()
                .all(|snapshot| snapshot.label != "20000101-000000-000")
        );
    }

    #[test]
    fn restore_backup_replaces_current_files_and_captures_pre_restore_snapshot() {
        let paths = test_paths("restore");
        paths.ensure_base_dirs().unwrap();

        std::fs::write(&paths.root_config, "Host current\n").unwrap();
        std::fs::write(
            paths.config_d_dir.join("010-host-current.conf"),
            "Host current\n  HostName current.example.com\n",
        )
        .unwrap();

        let snapshot_dir = paths.backups_dir.join("20260421-120000-000");
        std::fs::create_dir_all(snapshot_dir.join("config.d")).unwrap();
        std::fs::write(snapshot_dir.join("config.bak"), "Host restored\n").unwrap();
        std::fs::write(
            snapshot_dir.join("config.d").join("010-host-restored.conf"),
            "Host restored\n  HostName restored.example.com\n",
        )
        .unwrap();

        let outcome = restore_backup(
            &paths,
            &BackupSnapshot {
                path: snapshot_dir.clone(),
                label: "20260421-120000-000".to_string(),
                has_root_config: true,
                managed_file_count: 1,
            },
        )
        .unwrap();

        assert_eq!(outcome.restored_snapshot.label, "20260421-120000-000");
        assert_eq!(
            std::fs::read_to_string(&paths.root_config).unwrap(),
            "Host restored\n"
        );
        assert!(paths.config_d_dir.join("010-host-restored.conf").exists());
        assert!(!paths.config_d_dir.join("010-host-current.conf").exists());

        let pre_restore = outcome.pre_restore_backup_path.unwrap();
        assert_eq!(
            std::fs::read_to_string(pre_restore.join("config.bak")).unwrap(),
            "Host current\n"
        );
        assert!(
            pre_restore
                .join("config.d")
                .join("010-host-current.conf")
                .exists()
        );
    }

    #[test]
    fn restore_backup_removes_current_files_missing_from_snapshot() {
        let paths = test_paths("restore-remove");
        paths.ensure_base_dirs().unwrap();

        std::fs::write(&paths.root_config, "Host current\n").unwrap();
        std::fs::write(
            paths.config_d_dir.join("010-host-current.conf"),
            "Host current\n  HostName current.example.com\n",
        )
        .unwrap();

        let snapshot_dir = paths.backups_dir.join("20260421-130000-000");
        std::fs::create_dir_all(&snapshot_dir).unwrap();

        restore_backup(
            &paths,
            &BackupSnapshot {
                path: snapshot_dir,
                label: "20260421-130000-000".to_string(),
                has_root_config: false,
                managed_file_count: 0,
            },
        )
        .unwrap();

        assert!(!paths.root_config.exists());
        assert!(!paths.config_d_dir.exists());
    }
}
