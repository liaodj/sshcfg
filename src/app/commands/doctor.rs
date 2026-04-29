use anyhow::Result;

use crate::core::openssh;
use crate::core::root_config;
use crate::core::state;
use crate::core::store;
use crate::fs::backup;
use crate::fs::layout::{AppPaths, has_include_line, has_managed_block};

#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub ssh_dir: std::path::PathBuf,
    pub root_config: std::path::PathBuf,
    pub managed_dir: std::path::PathBuf,
    pub app_dir: std::path::PathBuf,
    pub backups_dir: std::path::PathBuf,
    pub state_file: std::path::PathBuf,
    pub backup_snapshot_count: usize,
    pub backup_retention_limit: usize,
    pub managed_entry_count: usize,
    pub state_version: u32,
    pub metadata_entry_count: usize,
    pub missing_metadata_count: usize,
    pub stale_metadata_count: usize,
    pub has_managed_block: bool,
    pub has_include_line: bool,
    pub root_match_block_count: usize,
    pub root_match_unsupported_block_count: usize,
    pub root_match_unsupported_conditions: Vec<String>,
    pub ssh_available: bool,
    pub ssh_version: Option<String>,
    pub ssh_error: Option<String>,
}

impl DoctorReport {
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "Doctor snapshot | {} managed | missing metadata {} | stale metadata {}",
            self.managed_entry_count, self.missing_metadata_count, self.stale_metadata_count
        );
        if self.root_match_unsupported_block_count > 0 {
            summary.push_str(&format!(
                " | unsupported root Match {}",
                self.root_match_unsupported_block_count
            ));
        }
        summary
    }

    pub fn detail_lines(&self) -> Vec<String> {
        let lines = vec![
            format!("ssh dir: {}", self.ssh_dir.display()),
            format!("root config: {}", self.root_config.display()),
            format!("managed dir: {}", self.managed_dir.display()),
            format!("app dir: {}", self.app_dir.display()),
            format!("backups dir: {}", self.backups_dir.display()),
            format!("state file: {}", self.state_file.display()),
            format!("backup snapshot count: {}", self.backup_snapshot_count),
            format!("backup retention limit: {}", self.backup_retention_limit),
            format!("managed entry count: {}", self.managed_entry_count),
            format!("state version: {}", self.state_version),
            format!("metadata entry count: {}", self.metadata_entry_count),
            format!("missing metadata count: {}", self.missing_metadata_count),
            format!("stale metadata count: {}", self.stale_metadata_count),
            format!("has managed block: {}", self.has_managed_block),
            format!("has include line: {}", self.has_include_line),
            format!("root Match block count: {}", self.root_match_block_count),
            format!(
                "unsupported root Match block count: {}",
                self.root_match_unsupported_block_count
            ),
            format!(
                "unsupported root Match conditions: {}",
                if self.root_match_unsupported_conditions.is_empty() {
                    "-".to_string()
                } else {
                    self.root_match_unsupported_conditions.join(" | ")
                }
            ),
            format!("ssh available: {}", self.ssh_available),
            format!(
                "ssh version: {}",
                self.ssh_version.as_deref().unwrap_or("-")
            ),
            format!("ssh error: {}", self.ssh_error.as_deref().unwrap_or("-")),
        ];
        lines
    }
}

pub fn collect_report(paths: &AppPaths) -> Result<DoctorReport> {
    let entries = store::load_managed_entries(paths)?;
    let state = state::load_state(paths)?;
    let summary = state::summarize_state(&state, &entries);
    let backups = backup::list_backups(paths)?;

    let (
        has_managed_block_flag,
        has_include_line_flag,
        root_match_block_count,
        root_match_unsupported_block_count,
        root_match_unsupported_conditions,
    ) = if paths.root_config.exists() {
        let content = std::fs::read_to_string(&paths.root_config)?;
        let root_match_blocks = root_config::extract_match_blocks(&content);
        (
            has_managed_block(&content),
            has_include_line(&content),
            root_match_blocks.len(),
            root_config::unsupported_match_block_count(&root_match_blocks),
            root_config::unsupported_match_conditions(&root_match_blocks),
        )
    } else {
        (false, false, 0, 0, Vec::new())
    };
    let probe = openssh::OpenSshProbe::discover();

    Ok(DoctorReport {
        ssh_dir: paths.ssh_dir.clone(),
        root_config: paths.root_config.clone(),
        managed_dir: paths.config_d_dir.clone(),
        app_dir: paths.app_dir.clone(),
        backups_dir: paths.backups_dir.clone(),
        state_file: paths.state_file.clone(),
        backup_snapshot_count: backups.len(),
        backup_retention_limit: backup::retention_limit(),
        managed_entry_count: entries.len(),
        state_version: state.version,
        metadata_entry_count: summary.metadata_entry_count,
        missing_metadata_count: summary.missing_metadata_count,
        stale_metadata_count: summary.stale_metadata_count,
        has_managed_block: has_managed_block_flag,
        has_include_line: has_include_line_flag,
        root_match_block_count,
        root_match_unsupported_block_count,
        root_match_unsupported_conditions,
        ssh_available: probe.available(),
        ssh_version: probe.version,
        ssh_error: probe.error,
    })
}

pub fn run() -> Result<()> {
    let paths = AppPaths::discover()?;
    let report = collect_report(&paths)?;

    for line in report.detail_lines() {
        println!("{line}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::core::model::HostEntry;
    use crate::core::store;
    use crate::fs::backup;
    use crate::fs::layout::{AppPaths, managed_block, platform_newline};

    use super::collect_report;

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-doctor")
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
    fn collect_report_summarizes_layout_and_metadata_gaps() {
        let paths = test_paths("summary");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let report = collect_report(&paths).unwrap();

        assert_eq!(report.managed_entry_count, 1);
        assert_eq!(report.backup_snapshot_count, 0);
        assert_eq!(report.backup_retention_limit, backup::retention_limit());
        assert_eq!(report.state_version, 1);
        assert_eq!(report.metadata_entry_count, 0);
        assert_eq!(report.missing_metadata_count, 1);
        assert_eq!(report.stale_metadata_count, 0);
        assert!(report.has_managed_block);
        assert!(report.has_include_line);
        assert_eq!(report.root_match_block_count, 0);
        assert_eq!(report.root_match_unsupported_block_count, 0);
        assert!(report.root_match_unsupported_conditions.is_empty());
    }

    #[test]
    fn collect_report_counts_root_match_blocks() {
        let paths = test_paths("match-count");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match user ops\n  PasswordAuthentication no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let report = collect_report(&paths).unwrap();

        assert_eq!(report.root_match_block_count, 1);
    }

    #[test]
    fn collect_report_lists_unsupported_root_match_conditions() {
        let paths = test_paths("match-unsupported");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match exec \"echo hi\" host alpha\n  PasswordAuthentication no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let report = collect_report(&paths).unwrap();

        assert_eq!(report.root_match_block_count, 1);
        assert_eq!(report.root_match_unsupported_block_count, 1);
        assert_eq!(
            report.root_match_unsupported_conditions,
            vec!["exec \"echo hi\"".to_string()]
        );
        assert!(report.summary().contains("unsupported root Match 1"));
    }
}
